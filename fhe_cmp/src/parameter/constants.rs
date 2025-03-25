use std::sync::LazyLock;

use algebra::{Field, U32FieldEval, modulus::PowOf2Modulus,U64FieldEval,reduce::ModulusValue};
use fhe_core::{LweSecretKeyType,RingSecretKeyType};

use super::{CmpFheParameters, ConstParameters, Steps};

type FpU32 = U32FieldEval<576716801>;

//P=132120577 lwe_cipher_modulus=28bit blind_rotation_basis_bits= 5
//P=576716801 lwe_cipher_modulus=31bit blind_rotation_basis_bits= 8

/// Default 128-bits security Parameters
pub static LVL1PARAM_128_BITS_PARAMETERS: LazyLock<CmpFheParameters<u32,PowOf2Modulus<u32>, FpU32>> =
    LazyLock::new(|| {
        CmpFheParameters::<u32,PowOf2Modulus<u32>, FpU32>::new(ConstParameters {
            lwe_dimension: 1024,
            lwe_plain_modulus: 2,
            lwe_cipher_modulus: ModulusValue::PowerOf2(1 << 31),
            lwe_noise_standard_deviation: 3.20,
            lwe_secret_key_type: LweSecretKeyType::Ternary,
            ring_dimension: 1024,
            ring_modulus: FpU32::MODULUS_VALUE,
            ring_noise_standard_deviation: 3.20 * ((1 << 1) as f64),
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 5,
            key_switching_basis_bits: 1,
            key_switching_standard_deviation: 3.2 * ((1 << 1) as f64),
            steps: Steps::BrMs,
        })
        .unwrap()
    });

type FpU64= U64FieldEval<4179340454199820289>;
//P=1205862401 lwe_cipher_modulus=32bit blind_rotation_basis_bits= 10
//P=20967325697 lwe_cipher_modulus=36bit blind_rotation_basis_bits= 11
//P=4179340454199820289 lwe_cipher_modulus=63bit blind_rotation_basis_bits= 13
/// Default 128-bits security Parameters
pub static LVL2PARAM_128_BITS_PARAMETERS: LazyLock<CmpFheParameters<u64,PowOf2Modulus<u64>, FpU64>> =
    LazyLock::new(|| {
        CmpFheParameters::<u64, PowOf2Modulus<u64>,FpU64>::new(ConstParameters {
            lwe_dimension: 2048,
            lwe_plain_modulus: 2,
            lwe_cipher_modulus: ModulusValue::PowerOf2(1 << 63),
            lwe_noise_standard_deviation: 3.20,
            lwe_secret_key_type: LweSecretKeyType::Ternary,
            ring_dimension: 2048,
            ring_modulus: FpU64::MODULUS_VALUE,
            ring_noise_standard_deviation: 3.20 * ((1 << 1) as f64),
            ring_secret_key_type: RingSecretKeyType::Ternary,
            blind_rotation_basis_bits: 13,
            key_switching_basis_bits: 3,
            key_switching_standard_deviation: 3.2 * ((1 << 1) as f64),
            steps: Steps::BrKsLevMs,
        })
        .unwrap()
    });