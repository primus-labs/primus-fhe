use algebra::derive::{DecomposableField, FheField, Field, Prime, NTT};
use fhe_core::{
    BlindRotationType, ConstParameters, LWESecretKeyType, ModulusSwitchRoundMethod, Parameters,
    RingSecretKeyType, Steps,
};
use once_cell::sync::Lazy;

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct FF(pub u64);

/// FF security default field
pub static DEFAULT_PARAMETERS: Lazy<Parameters<u64, FF>> = Lazy::new(|| {
    Parameters::<u64, FF>::new(ConstParameters {
        lwe_dimension: 1024,
        lwe_cipher_modulus: 2048,
        lwe_plain_modulus: 8,
        lwe_noise_standard_deviation: 3.20,
        lwe_secret_key_type: LWESecretKeyType::Binary,
        blind_rotation_type: BlindRotationType::RLWE,
        ring_dimension: 1024,
        ring_modulus: 132120577,
        ring_noise_standard_deviation: 3.20 * ((1 << 1) as f64),
        ring_secret_key_type: RingSecretKeyType::Binary,
        blind_rotation_basis_bits: 7,
        key_switching_basis_bits: 1,
        key_switching_standard_deviation: 3.2 * ((1 << 1) as f64),
        modulus_switching_round_method: ModulusSwitchRoundMethod::Round,
        steps: Steps::BrMs,
    })
    .unwrap()
});
