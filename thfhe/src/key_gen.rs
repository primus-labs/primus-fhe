use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::DiscreteGaussian,
    Field, NttField,
};
use fhe_core::{
    BinaryBlindRotationKey, KeySwitchingParameters, LwePublicKey, LweSecretKeyType,
    NonPowOf2LweKeySwitchingKey, RingSecretKeyType,
};
use itertools::izip;
use lattice::{GadgetRlwe, Lwe, NttGadgetRlwe, NttRgsw, NttRlwe, Rgsw, Rlwe};
use mpc::MPCBackend;
use rand::{CryptoRng, Rng};

use crate::{
    generate_share_ntt_rlwe_ciphertext_vec, generate_shared_binary_slices,
    generate_shared_lwe_ciphertext_vec, generate_shared_ternary_slices, EvaluationKey, Fp,
    MPCSecretKeyPack, ThFheParameters,
};

/// Struct of key generation.
pub struct KeyGen;

impl KeyGen {
    /// Generate key pair
    #[inline]
    pub fn generate_mpc_key_pair<Backend, R>(
        backend: &mut Backend,
        params: ThFheParameters,
        rng: &mut R,
    ) -> (MPCSecretKeyPack<Backend>, LwePublicKey<u64>, EvaluationKey)
    where
        R: Rng + CryptoRng,

        Backend: MPCBackend,
    {
        let id = backend.party_id();

        //let start = std::time::Instant::now();
        let sk = MPCSecretKeyPack::new(backend, params);
        // println!(
        //     "Party {} had finished the secret key pack with time {:?}",
        //     id,
        //     start.elapsed()
        // );

        let input_lwe_params = params.input_lwe_params();
        let key_switching_params = params.key_switching_params();
        let blind_rotation_params = params.blind_rotation_params();

        let start = std::time::Instant::now();
        let kappa = input_lwe_params.dimension
            * input_lwe_params.cipher_modulus_value.log_modulus() as usize;
        // let kappa = input_lwe_params.cipher_modulus_value.log_modulus() as usize;

        let lwe_public_key: LwePublicKey<u64> = generate_lwe_public_key(
            backend,
            sk.input_lwe_secret_key.as_ref(),
            input_lwe_params.noise_distribution(),
            kappa,
            rng,
        )
        .into();

        println!(
            "Party {} had finished the lwe public key with time {:?}",
            id,
            start.elapsed()
        );

        let start = std::time::Instant::now();
        let key_switching_key_basis: NonPowOf2ApproxSignedBasis<u64> =
            NonPowOf2ApproxSignedBasis::new(
                blind_rotation_params.modulus,
                key_switching_params.log_basis,
                key_switching_params.reverse_length,
            );

        let key_switching_key = generate_key_switching_key(
            backend,
            sk.input_lwe_secret_key.as_ref(),
            sk.intermediate_lwe_secret_key.as_ref(),
            key_switching_params.noise_distribution_for_Q::<Fp>(),
            key_switching_key_basis,
            rng,
        )
        .to_fhe_ksk(key_switching_params, key_switching_key_basis);
        println!(
            "Party {} had finished the key switching key with time {:?}",
            id,
            start.elapsed()
        );

        let start = std::time::Instant::now();
        let bootstrapping_key: BinaryBlindRotationKey<Fp> = generate_bootstrapping_key(
            backend,
            sk.intermediate_lwe_secret_key.as_ref(),
            sk.rlwe_secret_key.0.as_ref(),
            blind_rotation_params.noise_distribution(),
            blind_rotation_params.basis,
            rng,
        )
        .to_fhe_binary_bsk(blind_rotation_params.dimension);

        println!(
            "Party {} had finished the bootstrapping key with time {:?}",
            id,
            start.elapsed()
        );

        (
            sk,
            lwe_public_key,
            EvaluationKey::new(key_switching_key, bootstrapping_key, params),
        )
    }
}

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

pub fn generate_shared_lwe_secret_key<Backend>(
    backend: &mut Backend,
    secret_key_type: LweSecretKeyType,
    dimension: usize,
) -> MPCLweSecretKey<Backend::Sharing>
where
    Backend: MPCBackend,
{
    let s = match secret_key_type {
        LweSecretKeyType::Binary => generate_shared_binary_slices(backend, dimension),
        LweSecretKeyType::Ternary => generate_shared_ternary_slices(backend, dimension),
    };
    MPCLweSecretKey(s)
}

#[derive(Clone)]
pub struct MPCRlweSecretKey<Share>(pub Vec<Share>);

pub fn generate_shared_rlwe_secret_key<Backend>(
    backend: &mut Backend,
    secret_key_type: RingSecretKeyType,
    dimension: usize,
) -> MPCRlweSecretKey<Backend::Sharing>
where
    Backend: MPCBackend,
{
    let z = match secret_key_type {
        RingSecretKeyType::Binary => generate_shared_binary_slices(backend, dimension),
        RingSecretKeyType::Ternary => generate_shared_ternary_slices(backend, dimension),
        RingSecretKeyType::Gaussian => unreachable!("Gaussian secret key is not supported"),
    };

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
    let batch_mpc_lwe =
        generate_shared_lwe_ciphertext_vec(backend, lwe_secret_key, kappa, gaussian, rng);
    let b = backend
        .reveal_slice_to_all(batch_mpc_lwe.b.as_slice())
        .unwrap();
    MPCLwePublicKey(
        batch_mpc_lwe
            .a
            .into_iter()
            .zip(b.iter())
            .map(|(a, b)| RevealLwe { a, b: *b })
            .collect(),
    )
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct RevealNttRlwe {
    pub a: Vec<u64>,
    pub b: Vec<u64>,
}

impl<F> Into<NttRlwe<F>> for RevealNttRlwe
where
    F: Field<ValueT = u64> + NttField,
{
    #[inline]
    fn into(self) -> NttRlwe<F> {
        NttRlwe::new(
            FieldNttPolynomial::new(self.a),
            FieldNttPolynomial::new(self.b),
        )
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct RevealNttGadgetRlwe(pub Vec<RevealNttRlwe>, pub NonPowOf2ApproxSignedBasis<u64>);

impl<F> Into<NttGadgetRlwe<F>> for RevealNttGadgetRlwe
where
    F: Field<ValueT = u64> + NttField,
{
    #[inline]
    fn into(self) -> NttGadgetRlwe<F> {
        NttGadgetRlwe::new(self.0.into_iter().map(Into::into).collect(), self.1)
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct RevealNttRgsw {
    pub m: RevealNttGadgetRlwe,
    pub minus_z_m: RevealNttGadgetRlwe,
}

impl<F> Into<NttRgsw<F>> for RevealNttRgsw
where
    F: Field<ValueT = u64> + NttField,
{
    #[inline]
    fn into(self) -> NttRgsw<F> {
        NttRgsw::new(self.minus_z_m.into(), self.m.into())
    }
}

pub struct MPCBootstrappingKey(pub Vec<RevealRgsw>);

pub struct MPCNttBootstrappingKey(pub Vec<RevealNttRgsw>);

impl MPCNttBootstrappingKey {
    pub fn to_fhe_binary_bsk<F>(self, dimension: usize) -> BinaryBlindRotationKey<F>
    where
        F: Field<ValueT = u64> + NttField,
    {
        let temp: Vec<NttRgsw<F>> = self.0.into_iter().map(Into::into).collect();

        let ntt_table = F::generate_ntt_table(dimension.trailing_zeros()).unwrap();

        BinaryBlindRotationKey::new(temp, Arc::new(ntt_table))
    }
}

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
) -> MPCNttBootstrappingKey
where
    Backend: MPCBackend,
    R: Rng,
{
    let n = lwe_secret_key.len();
    let l = basis.decompose_length();
    let big_n = rlwe_secret_key.len();

    // println!("n: {}, l: {}, big_n: {}", n, l, big_n);

    let basis_scalar = basis.scalar_iter().collect::<Vec<_>>();

    let mut ntt_rlwe_secret_key = rlwe_secret_key.to_vec();
    backend.ntt_sharing_poly_inplace(&mut ntt_rlwe_secret_key);

    let mut batch_mpc_ntt_rlwe = generate_share_ntt_rlwe_ciphertext_vec(
        backend,
        rlwe_secret_key,
        &ntt_rlwe_secret_key,
        2 * n * l,
        gaussian,
        rng,
    );

    for (si, b_x) in izip!(
        lwe_secret_key.iter(),
        batch_mpc_ntt_rlwe.b.chunks_exact_mut(2 * big_n * l)
    ) {
        let (m, minus_z_m) = b_x.split_at_mut(big_n * l);

        m.chunks_exact_mut(big_n)
            .zip(basis_scalar.iter())
            .for_each(|(mi, scalar)| {
                let scaled_si = backend.mul_const(*si, *scalar);
                mi.iter_mut().for_each(|mij| {
                    *mij = backend.add(*mij, scaled_si);
                });
            });

        minus_z_m
            .chunks_exact_mut(big_n)
            .zip(basis_scalar.iter())
            .for_each(|(mi, scalar)| {
                let scaled_si = backend.mul_const(*si, *scalar);

                mi.iter_mut()
                    .zip(ntt_rlwe_secret_key.iter())
                    .for_each(|(mij, &zi)| {
                        *mij = backend.sub(*mij, backend.mul_local(zi, scaled_si));
                    });
            });
    }

    // let b = backend
    //     .reveal_slice_degree_2t_to_all(batch_mpc_ntt_rlwe.b.as_slice())
    //     .unwrap();
    // let b = batch_mpc_ntt_rlwe
    //     .b
    //     .as_slice()
    //     .chunks_exact( big_n * l)
    //     .map(|b_chunk| backend.reveal_slice_degree_2t_to_all(b_chunk).unwrap())
    //     .concat();

    let mut a_iter = batch_mpc_ntt_rlwe.a.into_iter();

    MPCNttBootstrappingKey(
        batch_mpc_ntt_rlwe
            .b
            .as_slice()
            .chunks_exact(2 * big_n * l)
            .map(|b_chunk| backend.reveal_slice_degree_2t_to_all(b_chunk).unwrap())
            // b.chunks_exact(2 * big_n * l)
            .map(|b_x| {
                let (m_slice, minus_z_m_slice) = b_x.split_at(big_n * l);
                RevealNttRgsw {
                    m: RevealNttGadgetRlwe(
                        m_slice
                            .chunks_exact(big_n)
                            .map(|b| RevealNttRlwe {
                                a: a_iter.next().unwrap(),
                                b: b.to_vec(),
                            })
                            .collect(),
                        basis,
                    ),
                    minus_z_m: RevealNttGadgetRlwe(
                        minus_z_m_slice
                            .chunks_exact(big_n)
                            .map(|b| RevealNttRlwe {
                                a: a_iter.next().unwrap(),
                                b: b.to_vec(),
                            })
                            .collect(),
                        basis,
                    ),
                }
            })
            .collect(),
    )
}

pub struct RevealGadgetLwe(pub Vec<RevealLwe>);

pub struct MPCKeySwitchingKey(pub Vec<Vec<RevealLwe>>);

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
                .map(|lwe| lwe.into_iter().map(Into::into).collect())
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
    let n = input_secret_key.len();
    let l = basis.decompose_length();

    let mut batch_mpc_lwe =
        generate_shared_lwe_ciphertext_vec(backend, output_secret_key, n * l, gaussian, rng);

    for (x, scalar) in batch_mpc_lwe.b.chunks_exact_mut(n).zip(basis.scalar_iter()) {
        for (b, s) in x.iter_mut().zip(input_secret_key.iter()) {
            let scaled_si = backend.mul_const(*s, scalar);
            *b = backend.add(*b, scaled_si);
        }
    }

    let b = backend
        .reveal_slice_to_all(batch_mpc_lwe.b.as_slice())
        .unwrap();

    let mut a_iter = batch_mpc_lwe.a.into_iter();

    MPCKeySwitchingKey(
        b.chunks_exact(n)
            .map(|b_x| {
                b_x.iter()
                    .map(|b_x_s| RevealLwe {
                        a: a_iter.next().unwrap(),
                        b: *b_x_s,
                    })
                    .collect()
            })
            .collect(),
    )
}
