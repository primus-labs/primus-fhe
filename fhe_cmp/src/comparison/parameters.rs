
use algebra::derive::{DecomposableField, FheField, Field, Prime, NTT};
use fhe_core::{BlindRotationType, ConstParameters,ModulusSwitchRoundMethod, Parameters,
    RingSecretKeyType, SecretKeyType, StepsAfterBR};
use once_cell::sync::Lazy;

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
///default size
pub struct Default(pub u64);
/// inner type
pub type Inner = u64;
/// ciphertext space
pub const FP: Inner = 132120577;
/// message space
pub const FT: Inner = 16;
///encode of 1
pub const DELTA: Default = Default((FP as f64 / FT as f64) as Inner);
///encode of 1/2
pub const HALF_DELTA: Default = Default((FP as f64 / (FT as f64 * 2.0)) as Inner);

/// Default 128-bits security Parameters
pub static DEFAULT_PARAMERTERS: Lazy<Parameters<u64, Default>> =
    Lazy::new(|| {
        Parameters::<u64, Default>::new(ConstParameters {
            lwe_dimension: 1024,
            lwe_modulus: 2048,
            t: 16,
            lwe_noise_std_dev: 3.20,
            secret_key_type: SecretKeyType::Binary,
            blind_rotation_type: BlindRotationType::RLWE,
            ring_dimension: 1024,
            ring_modulus: 132120577,
            ring_noise_std_dev: 3.20 * ((1 << 1) as f64),
            ring_secret_key_type: RingSecretKeyType::Binary,
            blind_rotation_basis_bits: 1,
            steps_after_blind_rotation: StepsAfterBR::Ms,
            key_switching_basis_bits: 1,
            key_switching_std_dev: 3.2 * ((1 << 1) as f64),
            modulus_switcing_round_method: ModulusSwitchRoundMethod::Round,
        })
        .unwrap()
    });
