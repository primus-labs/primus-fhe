use algebra::Field;
use fhe_core::{
    BlindRotationType, ConstParameters, DefaultFieldU32, LWESecretKeyType,
    ModulusSwitchRoundMethod, Parameters, RingSecretKeyType, StepsAfterBR,
};
use once_cell::sync::Lazy;

/// Default 128-bits security Parameters
pub static DEFAULT_TERNARY_128_BITS_NTRU_PARAMERTERS: Lazy<
    Parameters<u16, DefaultFieldU32, DefaultFieldU32>,
> = Lazy::new(|| {
    Parameters::<u16, DefaultFieldU32, DefaultFieldU32>::new(ConstParameters {
        lwe_dimension: 590,
        lwe_cipher_modulus: 1024,
        lwe_plain_modulus: 4,
        lwe_noise_standard_deviation: 3.20,
        secret_key_type: LWESecretKeyType::Ternary,
        blind_rotation_type: BlindRotationType::NTRU,
        ring_dimension: 1024,
        ring_modulus: DefaultFieldU32::MODULUS_VALUE,
        ring_noise_standard_deviation: 3.20 * 2.175,
        ring_secret_key_type: RingSecretKeyType::Ternary,
        blind_rotation_basis_bits: 6,
        steps_after_blind_rotation: StepsAfterBR::KsMs,
        key_switching_basis_bits: 1,
        key_switching_standard_deviation: 3.2 * ((1 << 12) as f64),
        modulus_switcing_round_method: ModulusSwitchRoundMethod::Floor,
        key_switching_modulus: DefaultFieldU32::MODULUS_VALUE,
    })
    .unwrap()
});
