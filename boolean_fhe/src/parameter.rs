use algebra::{derive::*, modulus::PowOf2Modulus, Basis, NTTField, Random, RandomNTTField, Ring};

use num_traits::cast;
use once_cell::sync::Lazy;

use crate::{FHEError, LWEValue, LWEValueNormal, SecretKeyType};

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<Scalar> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: u32,
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
    lwe_modulus: PowOf2Modulus<LWEValue>,
    /// The lwe noise error's standard deviation
    lwe_noise_std_dev: f64,
    /// LWE Secret Key distribution Type
    secret_key_type: SecretKeyType,

    /// RLWE polynomial dimension, refers to **`N`** in the paper.
    rlwe_dimension: usize,
    /// RLWE cipher modulus, refers to **`Q`** in the paper.
    rlwe_modulus: F::Inner,
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
    F::Inner: std::cmp::PartialEq<Scalar>,
    Scalar: std::fmt::Debug,
{
    type Error = FHEError;

    fn try_from(parameters: ConstParameters<Scalar>) -> Result<Self, FHEError> {
        assert_eq!(F::modulus_value(), parameters.rlwe_modulus);

        Self::new(
            parameters.lwe_dimension,
            parameters.rlwe_dimension,
            parameters.lwe_modulus,
            parameters.secret_key_type,
            parameters.gadget_basis_bits,
            parameters.key_switching_basis_bits,
            parameters.lwe_noise_std_dev,
            parameters.rlwe_noise_std_dev,
            parameters.key_switching_std_dev,
        )
    }
}

impl<F: NTTField> Parameters<F> {
    /// Creates a new [`Parameters<F>`].
    #[allow(clippy::too_many_arguments)] // This will be modified when remove `Ring`.
    pub fn new(
        lwe_dimension: usize,
        rlwe_dimension: usize,
        lwe_modulus: LWEValue,
        secret_key_type: SecretKeyType,
        gadget_basis_bits: u32,
        key_switching_basis_bits: u32,
        lwe_noise_std_dev: f64,
        rlwe_noise_std_dev: f64,
        key_switching_std_dev: f64,
    ) -> Result<Self, FHEError> {
        if !lwe_dimension.is_power_of_two() {
            return Err(FHEError::LweDimensionUnValid(lwe_dimension));
        }
        // N = 2^i
        if !rlwe_dimension.is_power_of_two() {
            return Err(FHEError::RlweDimensionUnValid(rlwe_dimension));
        }

        let rlwe_modulus = F::modulus_value();

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
        let rlwe_modulus_u = cast::<<F as Ring>::Inner, usize>(rlwe_modulus).unwrap();
        let temp = (rlwe_modulus_u - 1) / (rlwe_dimension << 1);
        if temp * (rlwe_dimension << 1) != (rlwe_modulus_u - 1) {
            return Err(FHEError::RLweModulusRlweDimensionNotCompatible {
                rlwe_modulus: rlwe_modulus_u,
                rlwe_dimension,
            });
        }

        let gadget_basis = <Basis<F>>::new(gadget_basis_bits);
        let bf = gadget_basis.basis();

        let mut gadget_basis_powers = vec![F::ZERO; gadget_basis.decompose_len()];
        let mut temp = F::ONE.inner();
        gadget_basis_powers.iter_mut().for_each(|v| {
            *v = F::new(temp);
            temp = temp * bf;
        });

        let key_switching_basis = <Basis<F>>::new(key_switching_basis_bits);

        Ok(Self {
            lwe_dimension,
            lwe_modulus: <PowOf2Modulus<LWEValue>>::new(lwe_modulus),
            lwe_noise_std_dev,
            secret_key_type,

            rlwe_dimension,
            rlwe_modulus,
            rlwe_noise_std_dev,

            lwe_modulus_f64: lwe_modulus as f64,
            rlwe_modulus_f64: cast::<<F as Ring>::Inner, f64>(rlwe_modulus).unwrap(),
            twice_rlwe_dimension_div_lwe_modulus,

            gadget_basis,
            gadget_basis_powers,

            key_switching_basis,
            key_switching_std_dev,
        })
    }

    /// Returns the lwe dimension of this [`Parameters<F>`], refers to **`n`** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_dimension
    }

    /// Returns the lwe modulus of this [`Parameters<F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus(&self) -> PowOf2Modulus<LWEValue> {
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
    pub fn rlwe_modulus(&self) -> <F as Ring>::Inner {
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
}

impl<F: NTTField> Parameters<F> {
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

/// Default Field for Default Parameters
#[derive(Ring, Field, Random, Prime, NTT)]
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
    gadget_basis_bits: 6,
    key_switching_basis_bits: 3,
    key_switching_std_dev: (1u32 << 12) as f64,
};

/// Default 100bits security Parameters
pub static DEFAULT_100_BITS_PARAMERTERS: Lazy<Parameters<DefaultField100>> = Lazy::new(|| {
    <Parameters<DefaultField100>>::try_from(CONST_DEFAULT_100_BITS_PARAMERTERS).unwrap()
});
