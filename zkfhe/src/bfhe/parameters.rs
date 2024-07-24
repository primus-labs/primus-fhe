use std::marker::PhantomData;

use algebra::Field;
use fhe_core::{
    BlindRotationType, ConstParameters, DefaultFieldU32, ModulusSwitchRoundMethod, Parameters,
    RingSecretKeyType, SecretKeyType, StepsAfterBR,
};
use once_cell::sync::Lazy;

/// Default 128-bits security Parameters
pub static DEFAULT_TERNARY_128_BITS_PARAMERTERS: Lazy<Parameters<bool, u16, DefaultFieldU32>> =
    Lazy::new(|| {
        Parameters::<bool, u16, DefaultFieldU32>::new(ConstParameters {
            lwe_dimension: 1024,
            lwe_modulus: 1024,
            t: 4,
            lwe_noise_std_dev: 3.20,
            secret_key_type: SecretKeyType::Ternary,
            blind_rotation_type: BlindRotationType::RLWE,
            ring_dimension: 1024,
            ring_modulus: DefaultFieldU32::MODULUS_VALUE,
            ring_noise_std_dev: 3.20 * ((1 << 1) as f64),
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 3,
            steps_after_blind_rotation: StepsAfterBR::Ms,
            key_switching_basis_bits: 1,
            key_switching_std_dev: 3.2 * ((1 << 1) as f64),
            modulus_switcing_round_method: ModulusSwitchRoundMethod::Floor,
            phantom: PhantomData,
        })
        .unwrap()
    });
