use algebra::{derive::*, modulus::PowOf2Modulus, Basis, Field, NTTField, Random, RandomNTTField};

use num_traits::cast;
use once_cell::sync::Lazy;

use crate::{FHEError, LWEType, LWEValueNormal, SecretKeyType};

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<Scalar> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: LWEType,
    /// The lwe noise error's standard deviation
    pub lwe_noise_std_dev: f64,
    /// LWE Secret Key distribution Type
    pub secret_key_type: SecretKeyType,

    /// RLWE polynomial dimension, refers to **`N`** in the paper.
    pub rlwe_dimension: usize,
    /// RLWE cipher modulus, refers to **`Q`** in the paper.
    pub rlwe_modulus: Scalar,
    /// The rlwe noise error's standard deviation
    pub rlwe_noise_std_dev: f64,

    /// Decompose basis for `Q` used for bootstrapping accumulator
    pub gadget_basis_bits: u32,

    /// Decompose basis for `Q` used for key switching.
    pub key_switching_basis_bits: u32,
    /// The rlwe noise error's standard deviation for key switching.
    pub key_switching_std_dev: f64,
}

/// The parameters of the fully homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct Parameters<F: NTTField> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    lwe_modulus: PowOf2Modulus<LWEType>,
    /// The lwe noise error's standard deviation
    lwe_noise_std_dev: f64,
    /// LWE Secret Key distribution Type
    secret_key_type: SecretKeyType,

    /// RLWE polynomial dimension, refers to **`N`** in the paper.
    rlwe_dimension: usize,
    /// RLWE cipher modulus, refers to **`Q`** in the paper.
    rlwe_modulus: F::Value,
    /// The rlwe noise error's standard deviation
    rlwe_noise_std_dev: f64,

    /// LWE cipher modulus, refers to **`q`** in the paper.
    lwe_modulus_f64: f64,
    /// RLWE cipher modulus, refers to **`Q`** in the paper.
    rlwe_modulus_f64: f64,
    /// Refers to **`2N/q`** in the paper.
    twice_rlwe_dimension_div_lwe_modulus: usize,

    /// Decompose basis for `Q` used for bootstrapping accumulator
    gadget_basis: Basis<F>,
    /// The powers of gadget_basis
    gadget_basis_powers: Vec<F>,

    /// Decompose basis for `Q` used for key switching.
    key_switching_basis: Basis<F>,
    /// The rlwe noise error's standard deviation for key switching.
    key_switching_std_dev: f64,
}

impl<F: NTTField, Scalar> TryFrom<ConstParameters<Scalar>> for Parameters<F>
where
    F::Value: std::cmp::PartialEq<Scalar>,
    Scalar: std::fmt::Debug,
{
    type Error = FHEError;

    fn try_from(parameters: ConstParameters<Scalar>) -> Result<Self, FHEError> {
        assert_eq!(F::modulus_value(), parameters.rlwe_modulus);

        Self::builder()
            .lwe_dimension(parameters.lwe_dimension)
            .lwe_modulus(parameters.lwe_modulus)
            .lwe_noise_std_dev(parameters.lwe_noise_std_dev)
            .secret_key_type(parameters.secret_key_type)
            .rlwe_dimension(parameters.rlwe_dimension)
            .rlwe_modulus(F::modulus_value())
            .rlwe_noise_std_dev(parameters.rlwe_noise_std_dev)
            .gadget_basis_bits(parameters.gadget_basis_bits)
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
    pub fn lwe_modulus(&self) -> PowOf2Modulus<LWEType> {
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

    /// Returns the rlwe dimension of this [`Parameters<F>`], refers to **`N`** in the paper.
    #[inline]
    pub fn rlwe_dimension(&self) -> usize {
        self.rlwe_dimension
    }

    /// Returns the rlwe modulus of this [`Parameters<F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn rlwe_modulus(&self) -> <F as Field>::Value {
        self.rlwe_modulus
    }

    /// Returns the rlwe noise error's standard deviation of this [`Parameters<F>`].
    #[inline]
    pub fn rlwe_noise_std_dev(&self) -> f64 {
        self.rlwe_noise_std_dev
    }

    /// Returns the lwe modulus f64 value of this [`Parameters<F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus_f64(&self) -> f64 {
        self.lwe_modulus_f64
    }

    /// Returns the rlwe modulus f64 value of this [`Parameters<F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn rlwe_modulus_f64(&self) -> f64 {
        self.rlwe_modulus_f64
    }

    /// Returns the twice rlwe dimension divides lwe modulus of this [`Parameters<F>`], refers to **`2N/q`** in the paper.
    #[inline]
    pub fn twice_rlwe_dimension_div_lwe_modulus(&self) -> usize {
        self.twice_rlwe_dimension_div_lwe_modulus
    }

    /// Returns the gadget basis of this [`Parameters<F>`],
    /// which acts as the decompose basis for `Q` used for bootstrapping accumulator.
    #[inline]
    pub fn gadget_basis(&self) -> Basis<F> {
        self.gadget_basis
    }

    /// Returns the powers of gadget basis of this [`Parameters<F>`].
    #[inline]
    pub fn gadget_basis_powers(&self) -> &[F] {
        &self.gadget_basis_powers
    }

    /// Returns the key switching basis of this [`Parameters<F>`],
    /// which acts as the decompose basis for `Q` used for key switching.
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
    pub fn lwe_noise_distribution(&self) -> LWEValueNormal {
        LWEValueNormal::new(self.lwe_modulus.value(), 0.0, self.lwe_noise_std_dev).unwrap()
    }
}

impl<F: RandomNTTField> Parameters<F> {
    /// Gets the rlwe noise distribution.
    #[inline]
    pub fn rlwe_noise_distribution(&self) -> <F as Random>::NormalDistribution {
        F::normal_distribution(0.0, self.rlwe_noise_std_dev).unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution(&self) -> <F as Random>::NormalDistribution {
        F::normal_distribution(0.0, self.key_switching_std_dev).unwrap()
    }
}

/// The parameters builder of the fully homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct ParametersBuilder<F: NTTField> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: Option<usize>,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    lwe_modulus: Option<LWEType>,
    /// The lwe noise error's standard deviation
    lwe_noise_std_dev: Option<f64>,
    /// LWE Secret Key distribution Type
    secret_key_type: SecretKeyType,

    /// RLWE polynomial dimension, refers to **`N`** in the paper.
    rlwe_dimension: Option<usize>,
    /// RLWE cipher modulus, refers to **`Q`** in the paper.
    rlwe_modulus: Option<F::Value>,
    /// The rlwe noise error's standard deviation
    rlwe_noise_std_dev: Option<f64>,

    /// Decompose basis for `Q` used for bootstrapping accumulator
    gadget_basis_bits: u32,

    /// Decompose basis for `Q` used for key switching.
    key_switching_basis_bits: u32,
    /// The rlwe noise error's standard deviation for key switching.
    key_switching_std_dev: Option<f64>,
}

impl<F: NTTField> Default for ParametersBuilder<F> {
    fn default() -> Self {
        Self {
            lwe_dimension: None,
            lwe_modulus: None,
            lwe_noise_std_dev: None,
            secret_key_type: SecretKeyType::default(),
            rlwe_dimension: None,
            rlwe_modulus: None,
            rlwe_noise_std_dev: None,
            gadget_basis_bits: 1,
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
    pub fn lwe_dimension(mut self, lwe_dimension: usize) -> Self {
        self.lwe_dimension = Some(lwe_dimension);
        self
    }

    /// Sets the lwe modulus of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn lwe_modulus(mut self, lwe_modulus: LWEType) -> Self {
        self.lwe_modulus = Some(lwe_modulus);
        self
    }

    /// Sets the lwe noise error's standard deviation of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn lwe_noise_std_dev(mut self, lwe_noise_std_dev: f64) -> Self {
        self.lwe_noise_std_dev = Some(lwe_noise_std_dev);
        self
    }

    /// Sets the LWE Secret Key distribution Type of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn secret_key_type(mut self, secret_key_type: SecretKeyType) -> Self {
        self.secret_key_type = secret_key_type;
        self
    }

    /// Sets the RLWE polynomial dimension of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn rlwe_dimension(mut self, rlwe_dimension: usize) -> Self {
        self.rlwe_dimension = Some(rlwe_dimension);
        self
    }

    /// Sets the RLWE cipher modulus of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn rlwe_modulus(mut self, rlwe_modulus: F::Value) -> Self {
        self.rlwe_modulus = Some(rlwe_modulus);
        self
    }

    /// Sets the rlwe noise error's standard deviation of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn rlwe_noise_std_dev(mut self, rlwe_noise_std_dev: f64) -> Self {
        self.rlwe_noise_std_dev = Some(rlwe_noise_std_dev);
        self
    }

    /// Sets the gadget basis bits of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn gadget_basis_bits(mut self, gadget_basis_bits: u32) -> Self {
        self.gadget_basis_bits = gadget_basis_bits;
        self
    }

    /// Sets the key switching basis bits of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn key_switching_basis_bits(mut self, key_switching_basis_bits: u32) -> Self {
        self.key_switching_basis_bits = key_switching_basis_bits;
        self
    }

    /// Sets the rlwe noise error's standard deviation for key switching of this [`ParametersBuilder<F>`].
    #[inline]
    pub fn key_switching_std_dev(mut self, key_switching_std_dev: f64) -> Self {
        self.key_switching_std_dev = Some(key_switching_std_dev);
        self
    }

    /// Tries to build the [`Parameters<F>`].
    #[inline]
    pub fn build(self) -> Result<Parameters<F>, FHEError> {
        assert!(
            self.lwe_dimension.is_some()
                & self.lwe_modulus.is_some()
                & self.lwe_noise_std_dev.is_some()
                & self.rlwe_dimension.is_some()
                & self.rlwe_modulus.is_some()
                & self.rlwe_noise_std_dev.is_some()
                & self.key_switching_std_dev.is_some()
        );
        assert_eq!(F::modulus_value(), self.rlwe_modulus.unwrap());

        let lwe_dimension = self.lwe_dimension.unwrap();
        let lwe_modulus = self.lwe_modulus.unwrap();
        let rlwe_dimension = self.rlwe_dimension.unwrap();
        let rlwe_modulus = self.rlwe_modulus.unwrap();

        if !lwe_dimension.is_power_of_two() {
            return Err(FHEError::LweDimensionUnValid(lwe_dimension));
        }
        // N = 2^i
        if !rlwe_dimension.is_power_of_two() {
            return Err(FHEError::RlweDimensionUnValid(rlwe_dimension));
        }

        // q|2N
        let lwe_modulus_u = lwe_modulus as usize;
        let twice_rlwe_dimension_div_lwe_modulus = (rlwe_dimension << 1) / lwe_modulus_u;
        if twice_rlwe_dimension_div_lwe_modulus * lwe_modulus_u != (rlwe_dimension << 1) {
            return Err(FHEError::LweModulusRlweDimensionNotCompatible {
                lwe_modulus: lwe_modulus_u,
                rlwe_dimension,
            });
        }

        // 2N|(Q-1)
        let rlwe_modulus_u = cast::<<F as Field>::Value, usize>(rlwe_modulus).unwrap();
        let temp = (rlwe_modulus_u - 1) / (rlwe_dimension << 1);
        if temp * (rlwe_dimension << 1) != (rlwe_modulus_u - 1) {
            return Err(FHEError::RLweModulusRlweDimensionNotCompatible {
                rlwe_modulus: rlwe_modulus_u,
                rlwe_dimension,
            });
        }

        let gadget_basis = <Basis<F>>::new(self.gadget_basis_bits);
        let bf = gadget_basis.basis();

        let mut gadget_basis_powers = vec![F::ZERO; gadget_basis.decompose_len()];
        let mut temp = F::ONE.get();
        gadget_basis_powers.iter_mut().for_each(|v| {
            *v = F::new(temp);
            temp = temp * bf;
        });

        let key_switching_basis = <Basis<F>>::new(self.key_switching_basis_bits);

        let rlwe_modulus_f64 = F::new(rlwe_modulus).to_f64();
        Ok(Parameters::<F> {
            lwe_dimension,
            lwe_modulus: <PowOf2Modulus<LWEType>>::new(lwe_modulus),
            lwe_noise_std_dev: self.lwe_noise_std_dev.unwrap(),
            secret_key_type: self.secret_key_type,

            rlwe_dimension,
            rlwe_modulus,
            rlwe_noise_std_dev: self.rlwe_noise_std_dev.unwrap(),

            lwe_modulus_f64: lwe_modulus as f64,
            rlwe_modulus_f64,
            twice_rlwe_dimension_div_lwe_modulus,

            gadget_basis,
            gadget_basis_powers,

            key_switching_basis,
            key_switching_std_dev: self.key_switching_std_dev.unwrap(),
        })
    }
}

/// Default Field for Default Parameters
#[derive(Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct DefaultField100(u32);

/// Default Parameters
pub const CONST_DEFAULT_100_BITS_PARAMERTERS: ConstParameters<u32> = ConstParameters::<u32> {
    lwe_dimension: 512,
    lwe_modulus: 512,
    lwe_noise_std_dev: 3.20,
    secret_key_type: SecretKeyType::Ternary,
    rlwe_dimension: 1024,
    rlwe_modulus: 132120577,
    rlwe_noise_std_dev: 3.20,
    gadget_basis_bits: 1,
    key_switching_basis_bits: 3,
    key_switching_std_dev: (1u32 << 12) as f64,
};

/// Default 100bits security Parameters
pub static DEFAULT_100_BITS_PARAMERTERS: Lazy<Parameters<DefaultField100>> = Lazy::new(|| {
    <Parameters<DefaultField100>>::try_from(CONST_DEFAULT_100_BITS_PARAMERTERS).unwrap()
});
