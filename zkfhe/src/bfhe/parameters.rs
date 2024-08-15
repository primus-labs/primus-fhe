use algebra::Field;
use fhe_core::{
    BlindRotationType, ConstParameters, DefaultFieldU32, LWESecretKeyType,
    ModulusSwitchRoundMethod, Parameters, RingSecretKeyType, Steps,
};
use once_cell::sync::Lazy;

/// Default 128-bits security Parameters
pub static DEFAULT_TERNARY_128_BITS_PARAMERTERS: Lazy<Parameters<u16, DefaultFieldU32>> =
    Lazy::new(|| {
        Parameters::<u16, DefaultFieldU32>::new(ConstParameters {
            lwe_dimension: 1024,
            lwe_cipher_modulus: 1024,
            lwe_plain_modulus: 4,
            lwe_noise_standard_deviation: 3.20,
            lwe_secret_key_type: LWESecretKeyType::Ternary,
            blind_rotation_type: BlindRotationType::RLWE,
            ring_dimension: 1024,
            ring_modulus: DefaultFieldU32::MODULUS_VALUE,
            ring_noise_standard_deviation: 3.20 * ((1 << 1) as f64),
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 3,
            key_switching_basis_bits: 1,
            key_switching_standard_deviation: 3.2 * ((1 << 1) as f64),
            modulus_switcing_round_method: ModulusSwitchRoundMethod::Floor,
            steps: Steps::BrKsMs,
        })
        .unwrap()
    });

/// Default 128-bits security Parameters
pub static CUSTOM_TERNARY_128_BITS_PARAMERTERS: Lazy<Parameters<u16, DefaultFieldU32>> =
    Lazy::new(|| {
        Parameters::<u16, DefaultFieldU32>::new(ConstParameters {
            lwe_dimension: 512,
            lwe_cipher_modulus: 1 << 14,
            lwe_plain_modulus: 4,
            lwe_noise_standard_deviation: 3.20,
            lwe_secret_key_type: LWESecretKeyType::Ternary,
            blind_rotation_type: BlindRotationType::RLWE,
            ring_dimension: 1024,
            ring_modulus: DefaultFieldU32::MODULUS_VALUE,
            ring_noise_standard_deviation: 3.20 * ((1 << 1) as f64),
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 7,
            key_switching_basis_bits: 7,
            key_switching_standard_deviation: 3.2 * ((1 << 1) as f64),
            modulus_switcing_round_method: ModulusSwitchRoundMethod::Round,
            steps: Steps::BrMsKs,
        })
        .unwrap()
    });
