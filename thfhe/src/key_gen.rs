use algebra::{decompose::NonPowOf2ApproxSignedBasis, random::DiscreteGaussian};
use fhe_core::{LweSecretKeyType, RingSecretKeyType};
use mpc::MPCBackend;
use rand::Rng;

use crate::{
    generate_share_rlwe_ciphertext, generate_shared_binary_value,
    generate_shared_binary_value_two_field, generate_shared_lwe_ciphertext,
    generate_shared_ternary_value, generate_shared_ternary_value_two_field, MPCLwe, MPCRlwe,
};

pub fn generate_shared_lwe_secret_key<Backendq, BackendQ, R>(
    backend_q: &mut Backendq,
    backend_big_q: &mut BackendQ,
    secret_key_type: LweSecretKeyType,
    dimension: usize,
    rng: &mut R,
) -> (Vec<Backendq::Sharing>, Vec<BackendQ::Sharing>)
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
    (s_q, s_big_q)
}

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

pub struct MPCLwePublicKey(pub Vec<RevealLwe>);

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

pub struct RevealGadgetRlwe(pub Vec<RevealRlwe>);

pub struct RevealRgsw {
    pub m: RevealGadgetRlwe,
    pub minus_z_m: RevealGadgetRlwe,
}

pub struct MPCBootstrappingKey(pub Vec<RevealRgsw>);

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
                                let scaled_si = backend.mul_const(*si, scalar).unwrap();
                                b[0] = backend.add(b[0], scaled_si).unwrap();

                                let b = b
                                    .into_iter()
                                    .map(|v| backend.reveal_to_all(v).unwrap())
                                    .collect();
                                RevealRlwe { a, b }
                            })
                            .collect(),
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
                                let minus_si = backend.neg(*si).unwrap();
                                let scaled_si = backend.mul_const(minus_si, scalar).unwrap();
                                b.iter_mut().zip(rlwe_secret_key).for_each(|(bi, zi)| {
                                    let temp = backend.mul(*zi, scaled_si).unwrap();
                                    *bi = backend.add(*bi, temp).unwrap();
                                });

                                let b = b
                                    .into_iter()
                                    .map(|v| backend.reveal_to_all(v).unwrap())
                                    .collect();
                                RevealRlwe { a, b }
                            })
                            .collect(),
                    )
                };
                RevealRgsw { m, minus_z_m }
            })
            .collect(),
    )
}

pub struct RevealGadgetLwe(pub Vec<RevealLwe>);

pub struct MPCKeySwitchingKey(pub Vec<RevealGadgetLwe>);

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
                            let scaled_zi = backend.mul_const(*zi, scalar).unwrap();
                            let b = backend.add(b, scaled_zi).unwrap();
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
