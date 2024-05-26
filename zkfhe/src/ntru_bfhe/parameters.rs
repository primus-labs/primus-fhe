use algebra::Field;
use fhe_core::{ConstParameters, DefaultFieldU32, Parameters, SecretKeyType};
use once_cell::sync::Lazy;

/// Default 128-bits security Parameters
pub static DEFAULT_TERNARY_128_BITS_NTRU_PARAMERTERS: Lazy<Parameters<DefaultFieldU32>> =
    Lazy::new(|| {
        Parameters::<DefaultFieldU32>::new(ConstParameters {
            lwe_dimension: 512,
            lwe_modulus: 1024,
            lwe_noise_std_dev: 3.20,
            secret_key_type: SecretKeyType::Ternary,
            ring_dimension: 1024,
            ring_modulus: DefaultFieldU32::MODULUS_VALUE,
            ring_noise_std_dev: 3.20 * 2.175,
            blind_rotation_basis_bits: 7,
            key_switching_basis_bits: 5,
            key_switching_std_dev: 3.2 * ((1 << 7) as f64),
        })
        .unwrap()
    });
