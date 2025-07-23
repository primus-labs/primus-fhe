use std::sync::LazyLock;

use algebra::{reduce::ModulusValue, Field, U64FieldEval};
use fhe_core::{LweSecretKeyType, RingSecretKeyType};

use super::{ConstParameters, ThFheParameters};

pub type Fp = U64FieldEval<1125899906826241>;

/// Default 128-bits security Parameters
pub static DEFAULT_128_BITS_PARAMETERS: LazyLock<ThFheParameters> = LazyLock::new(|| {
    ThFheParameters::new(ConstParameters {
        lwe_dimension: 1024,
        lwe_plain_modulus: 1 << 4,
        lwe_cipher_modulus: ModulusValue::PowerOf2(4096),
        lwe_noise_standard_deviation: 3.666,
        lwe_secret_key_type: LweSecretKeyType::Binary,

        ring_dimension: 2048,
        ring_modulus: Fp::MODULUS_VALUE,
        ring_noise_standard_deviation: 3.666,
        ring_secret_key_type: RingSecretKeyType::Ternary,
        blind_rotation_basis_bits: 6,

        key_switching_basis_bits: 1,
        key_switching_standard_deviation: 3.40 * ((1 << 26) as f64),
    })
    .unwrap()
});
