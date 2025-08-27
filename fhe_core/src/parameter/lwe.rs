use algebra::{
    integer::UnsignedInteger,
    random::DiscreteGaussian,
    reduce::{ModulusValue, RingReduce},
};

use crate::LweSecretKeyType;

/// Lwe Parameters.
#[derive(Debug, Clone, Copy)]
pub struct LweParameters<LweValue: UnsignedInteger, LweModulus: RingReduce<LweValue>> {
    /// **LWE** vector dimension, refers to **n** in the paper.
    pub dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    pub plain_modulus_value: LweValue,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub cipher_modulus_value: ModulusValue<LweValue>,
    /// **LWE** cipher modulus minus one, refers to **q-1** in the paper.
    pub cipher_modulus_minus_one: LweValue,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub cipher_modulus: LweModulus,
    /// The distribution type of the LWE Secret Key.
    pub secret_key_type: LweSecretKeyType,
    /// **LWE** noise error's standard deviation.
    pub noise_standard_deviation: f64,
}

impl<LweValue: UnsignedInteger, LweModulus: RingReduce<LweValue>>
    LweParameters<LweValue, LweModulus>
{
    /// Creates a new [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn new(
        dimension: usize,
        plain_modulus_value: LweValue,
        cipher_modulus: LweModulus,
        secret_key_type: LweSecretKeyType,
        noise_standard_deviation: f64,
    ) -> Self {
        let cipher_modulus_minus_one = cipher_modulus.modulus_minus_one();
        let cipher_modulus_value = cipher_modulus.modulus_value();
        Self {
            dimension,
            plain_modulus_value,
            cipher_modulus_value,
            cipher_modulus_minus_one,
            cipher_modulus,
            secret_key_type,
            noise_standard_deviation,
        }
    }

    /// Returns the dimension of this [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the plain modulus value of this [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn plain_modulus_value(&self) -> LweValue {
        self.plain_modulus_value
    }

    /// Returns the cipher modulus value of this [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn cipher_modulus_value(&self) -> ModulusValue<LweValue> {
        self.cipher_modulus_value
    }

    /// Returns the cipher modulus minus one of this [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> LweValue {
        self.cipher_modulus_minus_one
    }

    /// Returns the cipher modulus of this [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn cipher_modulus(&self) -> LweModulus {
        self.cipher_modulus
    }

    /// Returns the secret key type of this [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn secret_key_type(&self) -> LweSecretKeyType {
        self.secret_key_type
    }

    /// Returns the noise standard deviation of this [`LweParameters<LweValue, LweModulus>`].
    #[inline]
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_standard_deviation
    }

    /// Gets the discrete gaussian noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> DiscreteGaussian<LweValue> {
        DiscreteGaussian::new(
            0.0,
            self.noise_standard_deviation,
            self.cipher_modulus_minus_one,
        )
        .unwrap()
    }

    /// Gets the discrete gaussian noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32) -> DiscreteGaussian<LweValue> {
        let var = self.noise_standard_deviation * self.noise_standard_deviation;
        let sigma = (var / count as f64).sqrt();
        DiscreteGaussian::new(0.0, sigma, self.cipher_modulus_minus_one).unwrap()
    }
}
