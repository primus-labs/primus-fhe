use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, polynomial::FieldPolynomial, random::DiscreteGaussian,
    Field, NttField,
};
use fhe_core::{
    BinaryBlindRotationKey, BlindRotationKey, KeySwitchingParameters, LwePublicKey,
    LweSecretKeyType, NonPowOf2LweKeySwitchingKey, RingSecretKeyType,
};
use lattice::{GadgetRlwe, Lwe, Rgsw, Rlwe};
use mpc::MPCBackend;
use rand::Rng;

use crate::{
    generate_share_rlwe_ciphertext, generate_shared_binary_value,
    generate_shared_binary_value_two_field, generate_shared_lwe_ciphertext,
    generate_shared_ternary_value, generate_shared_ternary_value_two_field, MPCLwe, MPCRlwe,
};

#[derive(Clone)]
pub struct MPCDoubleBackendLweSecretKey<Shareq, ShareQ>(pub Vec<Shareq>, pub Vec<ShareQ>);

#[derive(Clone)]
pub struct MPCLweSecretKey<Share>(pub Vec<Share>);

impl<Share> AsRef<[Share]> for MPCLweSecretKey<Share> {
    #[inline]
    fn as_ref(&self) -> &[Share] {
        &self.0
    }
}

impl<Share> MPCLweSecretKey<Share> {
    #[inline]
    pub fn new(secret_key: Vec<Share>) -> Self {
        MPCLweSecretKey(secret_key)
    }
}

pub fn generate_shared_lwe_secret_key<Backendq, BackendQ, R>(
    backend_q: &mut Backendq,
    backend_big_q: &mut BackendQ,
    secret_key_type: LweSecretKeyType,
    dimension: usize,
    rng: &mut R,
) -> MPCDoubleBackendLweSecretKey<Backendq::Sharing, BackendQ::Sharing>
where
    Backendq: MPCBackend,
    BackendQ: MPCBackend,
    R: Rng,
{
    let mut s_q: Vec<<Backendq as MPCBackend>::Sharing> = vec![Default::default(); dimension];
    let mut s_big_q: Vec<<BackendQ as MPCBackend>::Sharing> = vec![Default::default(); dimension];

    s_q.iter_mut()
        .zip(s_big_q.iter_mut())
        .for_each(|(s_q_i, s_big_q_i)| {
            (*s_q_i, *s_big_q_i) = match secret_key_type {
                LweSecretKeyType::Binary => {
                    generate_shared_binary_value_two_field(backend_q, backend_big_q, rng)
                }
                LweSecretKeyType::Ternary => {
                    generate_shared_ternary_value_two_field(backend_q, backend_big_q, rng)
                }
            };
        });
    MPCDoubleBackendLweSecretKey(s_q, s_big_q)
}

#[derive(Clone)]
pub struct MPCRlweSecretKey<Share>(pub Vec<Share>);

pub fn generate_shared_rlwe_secret_key<Backend, R>(
    backend: &mut Backend,
    secret_key_type: RingSecretKeyType,
    dimension: usize,
    rng: &mut R,
) -> MPCRlweSecretKey<Backend::Sharing>
where
    Backend: MPCBackend,
    R: Rng,
{
    let mut z: Vec<<Backend as MPCBackend>::Sharing> = vec![Default::default(); dimension];

    z.iter_mut().for_each(|z_i| {
        *z_i = match secret_key_type {
            RingSecretKeyType::Binary => generate_shared_binary_value(backend, rng),
            RingSecretKeyType::Ternary => generate_shared_ternary_value(backend, rng),
            RingSecretKeyType::Gaussian => unreachable!("Gaussian secret key is not supported"),
        };
    });
    MPCRlweSecretKey(z)
}

pub struct RevealLwe {
    pub a: Vec<u64>,
    pub b: u64,
}

impl Into<Lwe<u64>> for RevealLwe {
    #[inline]
    fn into(self) -> Lwe<u64> {
        Lwe::new(self.a, self.b)
    }
}

pub struct MPCLwePublicKey(pub Vec<RevealLwe>);

impl Into<LwePublicKey<u64>> for MPCLwePublicKey {
    #[inline]
    fn into(self) -> LwePublicKey<u64> {
        LwePublicKey::with_public_key(self.0.into_iter().map(Into::into).collect())
    }
}

pub fn generate_lwe_public_key<Backend, R>(
    backend: &mut Backend,
    lwe_secret_key: &[Backend::Sharing],
    gaussian: DiscreteGaussian<u64>,
    kappa: usize,
    rng: &mut R,
) -> MPCLwePublicKey
where
    Backend: MPCBackend,
    R: Rng,
{
    MPCLwePublicKey(
        (0..kappa)
            .map(|_| {
                let MPCLwe { a, b } =
                    generate_shared_lwe_ciphertext(backend, lwe_secret_key, gaussian, rng);

                RevealLwe {
                    a,
                    b: backend.reveal_to_all(b).unwrap(),
                }
            })
            .collect(),
    )
}

pub struct RevealRlwe {
    pub a: Vec<u64>,
    pub b: Vec<u64>,
}

impl<F> Into<Rlwe<F>> for RevealRlwe
where
    F: Field<ValueT = u64>,
{
    #[inline]
    fn into(self) -> Rlwe<F> {
        Rlwe::new(FieldPolynomial::new(self.a), FieldPolynomial::new(self.b))
    }
}

pub struct RevealGadgetRlwe(pub Vec<RevealRlwe>, pub NonPowOf2ApproxSignedBasis<u64>);

impl<F> Into<GadgetRlwe<F>> for RevealGadgetRlwe
where
    F: Field<ValueT = u64> + NttField,
{
    #[inline]
    fn into(self) -> GadgetRlwe<F> {
        GadgetRlwe::new(self.0.into_iter().map(Into::into).collect(), self.1)
    }
}

pub struct RevealRgsw {
    pub m: RevealGadgetRlwe,
    pub minus_z_m: RevealGadgetRlwe,
}

impl<F> Into<Rgsw<F>> for RevealRgsw
where
    F: Field<ValueT = u64> + NttField,
{
    #[inline]
    fn into(self) -> Rgsw<F> {
        Rgsw::new(self.minus_z_m.into(), self.m.into())
    }
}

pub struct MPCBootstrappingKey(pub Vec<RevealRgsw>);

impl MPCBootstrappingKey {
    pub fn to_fhe_binary_bsk<F>(self, dimension: usize) -> BinaryBlindRotationKey<F>
    where
        F: Field<ValueT = u64> + NttField,
    {
        let temp: Vec<Rgsw<F>> = self.0.into_iter().map(Into::into).collect();
        let ntt_table = F::generate_ntt_table(dimension.trailing_zeros()).unwrap();
        let temp = temp
            .into_iter()
            .map(|rgsw| rgsw.to_ntt_rgsw(&ntt_table))
            .collect();
        BinaryBlindRotationKey::new(temp, Arc::new(ntt_table))
    }
}

pub fn generate_bootstrapping_key<Backend, R>(
    backend: &mut Backend,
    lwe_secret_key: &[Backend::Sharing],
    rlwe_secret_key: &[Backend::Sharing],
    gaussian: DiscreteGaussian<u64>,
    basis: NonPowOf2ApproxSignedBasis<u64>,
    rng: &mut R,
) -> MPCBootstrappingKey
where
    Backend: MPCBackend,
    R: Rng,
{
    MPCBootstrappingKey(
        lwe_secret_key
            .iter()
            .map(|si| {
                let m = {
                    RevealGadgetRlwe(
                        basis
                            .scalar_iter()
                            .map(|scalar| {
                                let MPCRlwe { a, mut b } = generate_share_rlwe_ciphertext(
                                    backend,
                                    rlwe_secret_key,
                                    gaussian,
                                    rng,
                                );
                                let scaled_si = backend.mul_const(*si, scalar);
                                b[0] = backend.add(b[0], scaled_si);

                                let b = b
                                    .into_iter()
                                    .map(|v| backend.reveal_to_all(v).unwrap())
                                    .collect();
                                RevealRlwe { a, b }
                            })
                            .collect(),
                        basis,
                    )
                };
                let minus_z_m = {
                    RevealGadgetRlwe(
                        basis
                            .scalar_iter()
                            .map(|scalar| {
                                let MPCRlwe { a, mut b } = generate_share_rlwe_ciphertext(
                                    backend,
                                    rlwe_secret_key,
                                    gaussian,
                                    rng,
                                );
                                let minus_si = backend.neg(*si);
                                let scaled_si = backend.mul_const(minus_si, scalar);
                                b.iter_mut().zip(rlwe_secret_key).for_each(|(bi, zi)| {
                                    let temp = backend.mul(*zi, scaled_si).unwrap();
                                    *bi = backend.add(*bi, temp);
                                });

                                let b = b
                                    .into_iter()
                                    .map(|v| backend.reveal_to_all(v).unwrap())
                                    .collect();
                                RevealRlwe { a, b }
                            })
                            .collect(),
                        basis,
                    )
                };
                RevealRgsw { m, minus_z_m }
            })
            .collect(),
    )
}

pub struct RevealGadgetLwe(pub Vec<RevealLwe>);

pub struct MPCKeySwitchingKey(pub Vec<RevealGadgetLwe>);

impl MPCKeySwitchingKey {
    #[inline]
    pub fn to_fhe_ksk(
        self,
        params: KeySwitchingParameters,
        basis: NonPowOf2ApproxSignedBasis<u64>,
    ) -> NonPowOf2LweKeySwitchingKey<u64> {
        NonPowOf2LweKeySwitchingKey::new(
            self.0
                .into_iter()
                .map(|RevealGadgetLwe(lwe)| lwe.into_iter().map(Into::into).collect())
                .collect(),
            params,
            basis,
        )
    }
}

pub fn generate_key_switching_key<Backend, R>(
    backend: &mut Backend,
    input_secret_key: &[Backend::Sharing],
    output_secret_key: &[Backend::Sharing],
    gaussian: DiscreteGaussian<u64>,
    basis: NonPowOf2ApproxSignedBasis<u64>,
    rng: &mut R,
) -> MPCKeySwitchingKey
where
    Backend: MPCBackend,
    R: Rng,
{
    MPCKeySwitchingKey(
        input_secret_key
            .iter()
            .map(|zi| {
                RevealGadgetLwe(
                    basis
                        .scalar_iter()
                        .map(|scalar| {
                            let MPCLwe { a, b } = generate_shared_lwe_ciphertext(
                                backend,
                                output_secret_key,
                                gaussian,
                                rng,
                            );
                            let scaled_zi = backend.mul_const(*zi, scalar);
                            let b = backend.add(b, scaled_zi);
                            RevealLwe {
                                a,
                                b: backend.reveal_to_all(b).unwrap(),
                            }
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}
