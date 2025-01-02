use algebra::{integer::UnsignedInteger, random::DiscreteGaussian, Field};

/// Parameters for key switching.
#[derive(Debug, Clone, Copy)]
pub struct KeySwitchingParameters {
    pub in_cipher_dimension: usize,
    pub out_cipher_dimension: usize,
    pub log_modulus: u32,
    /// Decompose basis for `Q` or `q` used for key switching.
    pub log_basis: u32,
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
    #[allow(non_snake_case)]
    #[inline]
    pub fn noise_distribution_for_Q<Q: Field>(&self) -> DiscreteGaussian<<Q as Field>::ValueT> {
        DiscreteGaussian::new(0.0, self.noise_standard_deviation, Q::MINUS_ONE).unwrap()
    }
}
