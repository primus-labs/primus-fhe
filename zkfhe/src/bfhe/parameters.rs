use algebra::Field;
use fhe_core::{
    BlindRotationType, ConstParameters, DefaultFieldU32, Parameters, RingSecretKeyType,
    SecretKeyType, StepsAfterBr,
};
use once_cell::sync::Lazy;

/// Default 128-bits security Parameters
pub static DEFAULT_TERNARY_128_BITS_PARAMERTERS: Lazy<Parameters<DefaultFieldU32>> =
    Lazy::new(|| {
        Parameters::<DefaultFieldU32>::new(ConstParameters {
            lwe_dimension: 590,
            lwe_modulus: 1024,
            lwe_noise_std_dev: 3.20,
            secret_key_type: SecretKeyType::Ternary,
            blind_rotation_type: BlindRotationType::RLWE,
            ring_dimension: 1024,
            ring_modulus: DefaultFieldU32::MODULUS_VALUE,
            ring_noise_std_dev: 3.20,
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 7,
            steps_after_blind_rotation: StepsAfterBr::KsMs,
            key_switching_basis_bits: 1,
            key_switching_std_dev: 3.2 * ((1 << 12) as f64),
        })
        .unwrap()
    });
