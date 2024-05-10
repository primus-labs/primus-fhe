use algebra::{
    derive::*, modulus::PowOf2Modulus, Basis, Field, FieldDiscreteGaussianSampler, NTTField,
};

use lattice::DiscreteGaussian;
use once_cell::sync::Lazy;

use crate::{FHEError, LWEPlaintext, SecretKeyType};

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<Scalar> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: LWEPlaintext,
    /// The lwe noise error's standard deviation
    pub lwe_noise_std_dev: f64,
    /// LWE Secret Key distribution Type
    pub secret_key_type: SecretKeyType,

    /// NTRU polynomial dimension, refers to **`N`** in the paper.
    pub ntru_dimension: usize,
    /// NTRU cipher modulus, refers to **`Q`** in the paper.
    pub ntru_modulus: Scalar,
    /// The ntru noise error's standard deviation
    pub ntru_noise_std_dev: f64,

    /// Decompose basis for `Q` used for bootstrapping accumulator
    pub bootstrapping_basis_bits: u32,

    /// Decompose basis for `Q` used for key switching.
    pub key_switching_basis_bits: u32,
    /// The noise error's standard deviation for key switching.
    pub key_switching_std_dev: f64,
}

/// The parameters of the fully homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct Parameters<F: NTTField> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    lwe_modulus: PowOf2Modulus<LWEPlaintext>,
    /// The lwe noise error's standard deviation
    lwe_noise_std_dev: f64,
    /// LWE Secret Key distribution Type
    secret_key_type: SecretKeyType,

    /// NTRU polynomial dimension, refers to **`N`** in the paper.
    ntru_dimension: usize,
    /// NTRU cipher modulus, refers to **`Q`** in the paper.
    ntru_modulus: F::Value,
    /// The ntru noise error's standard deviation
    ntru_noise_std_dev: f64,

    /// LWE cipher modulus, refers to **`q`** in the paper.
    lwe_modulus_f64: f64,
    /// NTRU cipher modulus, refers to **`Q`** in the paper.
    ntru_modulus_f64: f64,
    /// Refers to **`2N/q`** in the paper.
    twice_ntru_dimension_div_lwe_modulus: usize,

    /// Decompose basis for `Q` used for bootstrapping accumulator
    bootstrapping_basis: Basis<F>,

    /// Decompose basis for `Q` used for key switching.
    key_switching_basis: Basis<F>,
    /// The noise error's standard deviation for key switching.
    key_switching_std_dev: f64,
}

impl<F: NTTField, Scalar> TryFrom<ConstParameters<Scalar>> for Parameters<F>
where
    F::Value: std::cmp::PartialEq<Scalar>,
    Scalar: std::fmt::Debug,
{
    type Error = FHEError;

    fn try_from(parameters: ConstParameters<Scalar>) -> Result<Self, FHEError> {
        assert_eq!(F::MODULUS_VALUE, parameters.ntru_modulus);

        Self::builder()
            .lwe_dimension(parameters.lwe_dimension)
            .lwe_modulus(parameters.lwe_modulus)
            .lwe_noise_std_dev(parameters.lwe_noise_std_dev)
            .secret_key_type(parameters.secret_key_type)
            .ntru_dimension(parameters.ntru_dimension)
            .ntru_modulus(F::MODULUS_VALUE)
            .ntru_noise_std_dev(parameters.ntru_noise_std_dev)
            .bootstrapping_basis_bits(parameters.bootstrapping_basis_bits)
            .key_switching_basis_bits(parameters.key_switching_basis_bits)
            .key_switching_std_dev(parameters.key_switching_std_dev)
            .build()
    }
}

impl<F: NTTField> Parameters<F> {
    /// Creates a builder for [`Parameters<F>`].
    #[inline]
    pub fn builder() -> ParametersBuilder<F> {
        <ParametersBuilder<F>>::new()
    }

    /// Returns the lwe dimension of this [`Parameters<F>`], refers to **`n`** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_dimension
    }

    /// Returns the lwe modulus of this [`Parameters<F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus(&self) -> PowOf2Modulus<LWEPlaintext> {
        self.lwe_modulus
    }

    /// Returns the lwe noise error's standard deviation of this [`Parameters<F>`].
    #[inline]
    pub fn lwe_noise_std_dev(&self) -> f64 {
        self.lwe_noise_std_dev
    }

    /// Returns the LWE Secret Key distribution Type of this [`Parameters<F>`].
    #[inline]
    pub fn secret_key_type(&self) -> SecretKeyType {
        self.secret_key_type
    }

    /// Returns the ntru dimension of this [`Parameters<F>`], refers to **`N`** in the paper.
    #[inline]
    pub fn ntru_dimension(&self) -> usize {
        self.ntru_dimension
    }

    /// Returns the ntru modulus of this [`Parameters<F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn ntru_modulus(&self) -> <F as Field>::Value {
        self.ntru_modulus
    }

    /// Returns the ntru noise error's standard deviation of this [`Parameters<F>`].
    #[inline]
    pub fn ntru_noise_std_dev(&self) -> f64 {
        self.ntru_noise_std_dev
    }

    /// Returns the lwe modulus f64 value of this [`Parameters<F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus_f64(&self) -> f64 {
        self.lwe_modulus_f64
    }

    /// Returns the ntru modulus f64 value of this [`Parameters<F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn ntru_modulus_f64(&self) -> f64 {
        self.ntru_modulus_f64
    }

    /// Returns the twice ntru dimension divides lwe modulus of this [`Parameters<F>`], refers to **`2N/q`** in the paper.
    #[inline]
    pub fn twice_ntru_dimension_div_lwe_modulus(&self) -> usize {
        self.twice_ntru_dimension_div_lwe_modulus
    }

    /// Returns the gadget basis of this [`Parameters<F>`],
    /// which acts as the decompose basis for `Q` used for bootstrapping accumulator.
    #[inline]
    pub fn bootstrapping_basis(&self) -> Basis<F> {
        self.bootstrapping_basis
    }

    /// Returns the key switching basis bits of this [`Parameters<F>`],
    /// which acts as the decompose basis used for key switching.
    #[inline]
    pub fn key_switching_basis(&self) -> Basis<F> {
        self.key_switching_basis
    }

    /// Returns the key switching std dev of this [`Parameters<F>`].
    #[inline]
    pub fn key_switching_std_dev(&self) -> f64 {
        self.key_switching_std_dev
    }

    /// Gets the lwe noise distribution.
    #[inline]
    pub fn lwe_noise_distribution(&self) -> DiscreteGaussian<LWEPlaintext> {
        DiscreteGaussian::new(self.lwe_modulus.value(), 0.0, self.lwe_noise_std_dev).unwrap()
    }

    /// Gets the ntru noise distribution.
    #[inline]
    pub fn ntru_noise_distribution(&self) -> FieldDiscreteGaussianSampler {
        FieldDiscreteGaussianSampler::new(0.0, self.ntru_noise_std_dev).unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution(&self) -> FieldDiscreteGaussianSampler {
        FieldDiscreteGaussianSampler::new(0.0, self.key_switching_std_dev).unwrap()
    }
}

/// The parameters builder of the fully homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct ParametersBuilder<F: NTTField> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: Option<usize>,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    lwe_modulus: Option<LWEPlaintext>,
    /// The lwe noise error's standard deviation
    lwe_noise_std_dev: Option<f64>,
    /// LWE Secret Key distribution Type
    secret_key_type: SecretKeyType,

    /// NTRU polynomial dimension, refers to **`N`** in the paper.
    ntru_dimension: Option<usize>,
    /// NTRU cipher modulus, refers to **`Q`** in the paper.
    ntru_modulus: Option<F::Value>,
    /// The ntru noise error's standard deviation
    ntru_noise_std_dev: Option<f64>,

    /// Decompose basis for `Q` used for bootstrapping accumulator
    bootstrapping_basis_bits: u32,

    /// Decompose basis for `Q` used for key switching.
    key_switching_basis_bits: u32,
    /// The ntru noise error's standard deviation for key switching.
    key_switching_std_dev: Option<f64>,
}

impl<F: NTTField> Default for ParametersBuilder<F> {
    fn default() -> Self {
        Self {
            lwe_dimension: None,
            lwe_modulus: None,
            lwe_noise_std_dev: None,
            secret_key_type: SecretKeyType::default(),
            ntru_dimension: None,
            ntru_modulus: None,
            ntru_noise_std_dev: None,
            bootstrapping_basis_bits: 1,
            key_switching_basis_bits: 1,
            key_switching_std_dev: None,
        }
    }
}

impl<F: NTTField> ParametersBuilder<F> {
    /// Creates a new [`ParametersBuilder<F>`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the lwe dimension of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn lwe_dimension(&mut self, lwe_dimension: usize) -> &mut Self {
        self.lwe_dimension = Some(lwe_dimension);
        self
    }

    /// Sets the lwe modulus of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn lwe_modulus(&mut self, lwe_modulus: LWEPlaintext) -> &mut Self {
        self.lwe_modulus = Some(lwe_modulus);
        self
    }

    /// Sets the lwe noise error's standard deviation of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn lwe_noise_std_dev(&mut self, lwe_noise_std_dev: f64) -> &mut Self {
        self.lwe_noise_std_dev = Some(lwe_noise_std_dev);
        self
    }

    /// Sets the LWE Secret Key distribution Type of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn secret_key_type(&mut self, secret_key_type: SecretKeyType) -> &mut Self {
        self.secret_key_type = secret_key_type;
        self
    }

    /// Sets the NTRU polynomial dimension of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn ntru_dimension(&mut self, ntru_dimension: usize) -> &mut Self {
        self.ntru_dimension = Some(ntru_dimension);
        self
    }

    /// Sets the NTRU cipher modulus of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn ntru_modulus(&mut self, ntru_modulus: F::Value) -> &mut Self {
        self.ntru_modulus = Some(ntru_modulus);
        self
    }

    /// Sets the ntru noise error's standard deviation of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn ntru_noise_std_dev(&mut self, ntru_noise_std_dev: f64) -> &mut Self {
        self.ntru_noise_std_dev = Some(ntru_noise_std_dev);
        self
    }

    /// Sets the gadget basis bits of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn bootstrapping_basis_bits(&mut self, bootstrapping_basis_bits: u32) -> &mut Self {
        self.bootstrapping_basis_bits = bootstrapping_basis_bits;
        self
    }

    /// Sets the key switching basis bits of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn key_switching_basis_bits(&mut self, key_switching_basis_bits: u32) -> &mut Self {
        self.key_switching_basis_bits = key_switching_basis_bits;
        self
    }

    /// Sets the noise error's standard deviation for key switching of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn key_switching_std_dev(&mut self, key_switching_std_dev: f64) -> &mut Self {
        self.key_switching_std_dev = Some(key_switching_std_dev);
        self
    }

    /// Tries to build the [`Parameters<F>`].
    #[inline]
    pub fn build(&self) -> Result<Parameters<F>, FHEError> {
        assert!(
            self.lwe_dimension.is_some()
                & self.lwe_modulus.is_some()
                & self.lwe_noise_std_dev.is_some()
                & self.ntru_dimension.is_some()
                & self.ntru_modulus.is_some()
                & self.ntru_noise_std_dev.is_some()
                & self.key_switching_std_dev.is_some()
        );
        assert_eq!(F::MODULUS_VALUE, self.ntru_modulus.unwrap());

        let lwe_dimension = self.lwe_dimension.unwrap();
        let lwe_modulus = self.lwe_modulus.unwrap();
        let ntru_dimension = self.ntru_dimension.unwrap();
        let ntru_modulus = self.ntru_modulus.unwrap();

        if !lwe_dimension.is_power_of_two() {
            return Err(FHEError::LweDimensionUnValid(lwe_dimension));
        }
        // N = 2^i
        if !ntru_dimension.is_power_of_two() {
            return Err(FHEError::NtruDimensionUnValid(ntru_dimension));
        }

        // q|2N
        let lwe_modulus_u = lwe_modulus as usize;
        let twice_ntru_dimension_div_lwe_modulus = (ntru_dimension << 1) / lwe_modulus_u;
        if twice_ntru_dimension_div_lwe_modulus * lwe_modulus_u != (ntru_dimension << 1) {
            return Err(FHEError::LweModulusNtruDimensionNotCompatible {
                lwe_modulus: lwe_modulus_u,
                ntru_dimension,
            });
        }

        // 2N|(Q-1)
        let t: u64 = ntru_modulus.into();
        let ntru_modulus_u: usize = t.try_into().unwrap();
        let temp = (ntru_modulus_u - 1) / (ntru_dimension << 1);
        if temp * (ntru_dimension << 1) != (ntru_modulus_u - 1) {
            return Err(FHEError::NtruModulusNtruDimensionNotCompatible {
                ntru_modulus: ntru_modulus_u,
                ntru_dimension,
            });
        }

        let bootstrapping_basis = <Basis<F>>::new(self.bootstrapping_basis_bits);

        let key_switching_basis = <Basis<F>>::new(self.key_switching_basis_bits);

        let ntru_modulus_f64 = ntru_modulus.into() as f64;
        Ok(Parameters::<F> {
            lwe_dimension,
            lwe_modulus: <PowOf2Modulus<LWEPlaintext>>::new(lwe_modulus),
            lwe_noise_std_dev: self.lwe_noise_std_dev.unwrap(),
            secret_key_type: self.secret_key_type,

            ntru_dimension,
            ntru_modulus,
            ntru_noise_std_dev: self.ntru_noise_std_dev.unwrap(),

            lwe_modulus_f64: lwe_modulus as f64,
            ntru_modulus_f64,
            twice_ntru_dimension_div_lwe_modulus,

            bootstrapping_basis,

            key_switching_basis,
            key_switching_std_dev: self.key_switching_std_dev.unwrap(),
        })
    }
}

/// Default Field for Default Parameters
#[derive(Field, Prime, NTT)]
#[modulus = 132120577]
pub struct DefaultFieldTernary128(u32);

/// Default Parameters
pub const CONST_DEFAULT_TERNARY_128_BITS_PARAMERTERS: ConstParameters<u32> = ConstParameters::<u32> {
    lwe_dimension: 512,
    lwe_modulus: 1024,
    lwe_noise_std_dev: 3.20,
    secret_key_type: SecretKeyType::Ternary,
    ntru_dimension: 1024,
    ntru_modulus: 132120577,
    ntru_noise_std_dev: 3.20 * 2.15,
    bootstrapping_basis_bits: 7,
    key_switching_basis_bits: 5,
    key_switching_std_dev: 3.2 * ((1 << 7) as f64),
};

/// Default 128-bits security Parameters
pub static DEFAULT_TERNARY_128_BITS_PARAMERTERS: Lazy<Parameters<DefaultFieldTernary128>> =
    Lazy::new(|| {
        <Parameters<DefaultFieldTernary128>>::try_from(CONST_DEFAULT_TERNARY_128_BITS_PARAMERTERS)
            .unwrap()
    });
