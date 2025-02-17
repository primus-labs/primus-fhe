use std::sync::LazyLock;

use algebra::{modulus::PowOf2Modulus, reduce::ModulusValue, Field, U32FieldEval};
use fhe_core::{LweSecretKeyType, RingSecretKeyType};

use super::{BooleanFheParameters, ConstParameters, Steps};

type Fp = U32FieldEval<132120577>;

/// Default 128-bits security Parameters
pub static DEFAULT_128_BITS_PARAMETERS: LazyLock<
    BooleanFheParameters<u16, PowOf2Modulus<u16>, Fp>,
> = LazyLock::new(|| {
    BooleanFheParameters::<u16, PowOf2Modulus<u16>, Fp>::new(ConstParameters {
        lwe_dimension: 512,
        lwe_plain_modulus: 4,
        lwe_cipher_modulus: ModulusValue::PowerOf2(1 << 14),
        lwe_noise_standard_deviation: 3.20,
        lwe_secret_key_type: LweSecretKeyType::Binary,
        ring_dimension: 1024,
        ring_modulus: Fp::MODULUS_VALUE,
        ring_noise_standard_deviation: 3.20 * ((1 << 1) as f64),
        ring_secret_key_type: RingSecretKeyType::Ternary,
        blind_rotation_basis_bits: 7,
        key_switching_basis_bits: 2,
        key_switching_standard_deviation: 3.2 * ((1 << 1) as f64),
        steps: Steps::BrKsLevMs,
    })
    .unwrap()
});
