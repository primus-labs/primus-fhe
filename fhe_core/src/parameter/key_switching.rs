use algebra::{integer::UnsignedInteger, random::DiscreteGaussian, Field};

/// Represents the parameters used for key switching in cryptographic schemes.
#[derive(Debug, Clone, Copy)]
pub struct KeySwitchingParameters {
    /// The dimension of the input ciphertext.
    pub input_cipher_dimension: usize,
    /// The dimension of the output ciphertext.
    pub output_cipher_dimension: usize,
    /// The logarithm of the modulus used in the scheme.
    pub log_modulus: u32,
    /// Decompose basis for `Q` or `q` used for key switching.
    pub log_basis: u32,
    /// The length of the decomposition, if applicable.
    pub reverse_length: Option<usize>,
    /// The noise error's standard deviation of key switching key.
    pub noise_standard_deviation: f64,
}

impl KeySwitchingParameters {
    /// Gets the discrete gaussian noise distribution.
    #[inline]
    pub fn noise_distribution_for_q<C: UnsignedInteger>(
        &self,
        modulus_minus_one: C,
    ) -> DiscreteGaussian<C> {
        DiscreteGaussian::new(0.0, self.noise_standard_deviation, modulus_minus_one).unwrap()
    }

    /// Gets the discrete gaussian noise distribution.
    #[inline]
    pub fn noise_distribution_for_q_div_count<C: UnsignedInteger>(
        &self,
        modulus_minus_one: C,
        count: u32,
    ) -> DiscreteGaussian<C> {
        let var = self.noise_standard_deviation * self.noise_standard_deviation;
        let sigma = (var / count as f64).sqrt();
        DiscreteGaussian::new(0.0, sigma, modulus_minus_one).unwrap()
    }

    /// Gets the discrete gaussian noise distribution.
    #[allow(non_snake_case)]
    #[inline]
    pub fn noise_distribution_for_Q<Q: Field>(&self) -> DiscreteGaussian<<Q as Field>::ValueT> {
        DiscreteGaussian::new(0.0, self.noise_standard_deviation, Q::MINUS_ONE).unwrap()
    }

    /// Gets the discrete gaussian noise distribution.
    #[allow(non_snake_case)]
    #[inline]
    pub fn noise_distribution_for_Q_div_count<Q: Field>(
        &self,
        count: u32,
    ) -> DiscreteGaussian<<Q as Field>::ValueT> {
        let var = self.noise_standard_deviation * self.noise_standard_deviation;
        let sigma = (var / count as f64).sqrt();
        DiscreteGaussian::new(0.0, sigma, Q::MINUS_ONE).unwrap()
    }
}
