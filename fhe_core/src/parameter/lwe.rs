use algebra::{integer::UnsignedInteger, random::DiscreteGaussian};

use crate::LweSecretKeyType;

use super::ModulusValue;

/// Lwe Parameters.
#[derive(Debug, Clone, Copy)]
pub struct LweParameters<C: UnsignedInteger> {
    /// **LWE** vector dimension, refers to **n** in the paper.
    pub dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    pub plain_modulus_value: C,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub cipher_modulus_value: ModulusValue<C>,
    /// **LWE** cipher modulus minus one, refers to **q-1** in the paper.
    pub cipher_modulus_minus_one: C,
    /// The distribution type of the LWE Secret Key.
    pub secret_key_type: LweSecretKeyType,
    /// **LWE** noise error's standard deviation.
    pub noise_standard_deviation: f64,
}

impl<C: UnsignedInteger> LweParameters<C> {
    /// Creates a new [`LweParameters<C>`].
    #[inline]
    pub fn new(
        dimension: usize,
        plain_modulus_value: C,
        cipher_modulus_value: ModulusValue<C>,
        secret_key_type: LweSecretKeyType,
        noise_standard_deviation: f64,
    ) -> Self {
        let cipher_modulus_minus_one = cipher_modulus_value.modulus_minus_one();
        Self {
            dimension,
            plain_modulus_value,
            cipher_modulus_value,
            cipher_modulus_minus_one,
            secret_key_type,
            noise_standard_deviation,
        }
    }

    /// Gets the discrete gaussian noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> DiscreteGaussian<C> {
        DiscreteGaussian::new(
            0.0,
            self.noise_standard_deviation,
            self.cipher_modulus_minus_one,
        )
        .unwrap()
    }
}
