use algebra::{derive::*, Basis, NTTField, Random, RandomNTTField, RandomRing, Ring};

use num_traits::cast;
use once_cell::sync::Lazy;

use crate::SecretKeyType;

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<Scalar> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: Scalar,
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

    /// Decompose basis for `Q` used for key switching
    pub key_switching_basis_bits: u32,
}

/// The parameters of the fully homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct Parameters<R: Ring, F: NTTField> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    lwe_modulus: R::Inner,
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

    /// Decompose basis for `Q` used for key switching
    key_switching_basis: Basis<F>,
    /// The powers of key_switch_basis
    key_switching_basis_powers: Vec<F>,
}

impl<R: Ring, F: NTTField, Scalar> From<ConstParameters<Scalar>> for Parameters<R, F>
where
    R::Inner: std::cmp::PartialEq<Scalar>,
    F::Inner: std::cmp::PartialEq<Scalar>,
    Scalar: std::fmt::Debug,
{
    fn from(parameters: ConstParameters<Scalar>) -> Self {
        assert_eq!(R::modulus_value(), parameters.lwe_modulus);
        assert_eq!(F::modulus_value(), parameters.rlwe_modulus);
        Self::new(
            parameters.lwe_dimension,
            parameters.rlwe_dimension,
            parameters.secret_key_type,
            parameters.gadget_basis_bits,
            parameters.key_switching_basis_bits,
            parameters.lwe_noise_std_dev,
            parameters.rlwe_noise_std_dev,
        )
    }
}

impl<R: Ring, F: NTTField> Parameters<R, F> {
    /// Creates a new [`Parameters<R, F>`].
    pub fn new(
        lwe_dimension: usize,
        rlwe_dimension: usize,
        secret_key_type: SecretKeyType,
        gadget_basis_bits: u32,
        key_switching_basis_bits: u32,
        lwe_noise_std_dev: f64,
        rlwe_noise_std_dev: f64,
    ) -> Self {
        let lwe_modulus = R::modulus_value();
        let rlwe_modulus = F::modulus_value();

        let gadget_basis = <Basis<F>>::new(gadget_basis_bits);
        let bf = gadget_basis.basis();

        let mut gadget_basis_powers = vec![F::ZERO; gadget_basis.decompose_len()];
        let mut temp = F::ONE.inner();
        gadget_basis_powers.iter_mut().for_each(|v| {
            *v = F::new(temp);
            temp = temp * bf;
        });

        let key_switching_basis = <Basis<F>>::new(key_switching_basis_bits);
        let bf = key_switching_basis.basis();

        let mut key_switching_basis_powers = vec![F::ZERO; key_switching_basis.decompose_len()];
        let mut temp = F::ONE.inner();
        key_switching_basis_powers.iter_mut().for_each(|v| {
            *v = F::new(temp);
            temp = temp * bf;
        });

        Self {
            lwe_dimension,
            lwe_modulus,
            lwe_noise_std_dev,
            secret_key_type,

            rlwe_dimension,
            rlwe_modulus,
            rlwe_noise_std_dev,

            lwe_modulus_f64: cast::<<R as Ring>::Inner, f64>(lwe_modulus).unwrap(),
            rlwe_modulus_f64: cast::<<F as Ring>::Inner, f64>(rlwe_modulus).unwrap(),
            twice_rlwe_dimension_div_lwe_modulus: (rlwe_dimension << 1)
                / cast::<<R as Ring>::Inner, usize>(lwe_modulus).unwrap(),

            gadget_basis,
            gadget_basis_powers,

            key_switching_basis,
            key_switching_basis_powers,
        }
    }

    /// Returns the lwe dimension of this [`Parameters<R, F>`], refers to **`n`** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_dimension
    }

    /// Returns the lwe modulus of this [`Parameters<R, F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus(&self) -> <R as Ring>::Inner {
        self.lwe_modulus
    }

    /// Returns the lwe noise error's standard deviation of this [`Parameters<R, F>`].
    #[inline]
    pub fn lwe_noise_std_dev(&self) -> f64 {
        self.lwe_noise_std_dev
    }

    /// Returns the LWE Secret Key distribution Type of this [`Parameters<R, F>`].
    #[inline]
    pub fn secret_key_type(&self) -> SecretKeyType {
        self.secret_key_type
    }

    /// Returns the rlwe dimension of this [`Parameters<R, F>`], refers to **`N`** in the paper.
    #[inline]
    pub fn rlwe_dimension(&self) -> usize {
        self.rlwe_dimension
    }

    /// Returns the rlwe modulus of this [`Parameters<R, F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn rlwe_modulus(&self) -> <F as Ring>::Inner {
        self.rlwe_modulus
    }

    /// Returns the rlwe noise error's standard deviation of this [`Parameters<R, F>`].
    #[inline]
    pub fn rlwe_noise_std_dev(&self) -> f64 {
        self.rlwe_noise_std_dev
    }

    /// Returns the lwe modulus f64 value of this [`Parameters<R, F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus_f64(&self) -> f64 {
        self.lwe_modulus_f64
    }

    /// Returns the rlwe modulus f64 value of this [`Parameters<R, F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn rlwe_modulus_f64(&self) -> f64 {
        self.rlwe_modulus_f64
    }

    /// Returns the twice rlwe dimension divides lwe modulus of this [`Parameters<R, F>`], refers to **`2N/q`** in the paper.
    #[inline]
    pub fn twice_rlwe_dimension_div_lwe_modulus(&self) -> usize {
        self.twice_rlwe_dimension_div_lwe_modulus
    }

    /// Returns the gadget basis of this [`Parameters<R, F>`],
    /// which acts as the decompose basis for `Q` used for bootstrapping accumulator.
    #[inline]
    pub fn gadget_basis(&self) -> Basis<F> {
        self.gadget_basis
    }

    /// Returns the powers of gadget basis of this [`Parameters<R, F>`].
    #[inline]
    pub fn gadget_basis_powers(&self) -> &[F] {
        &self.gadget_basis_powers
    }

    /// Returns the key switching basis of this [`Parameters<R, F>`],
    /// which acts as the decompose basis for `Q` used for key switching.
    #[inline]
    pub fn key_switching_basis(&self) -> Basis<F> {
        self.key_switching_basis
    }

    /// Returns the powers of key switch basis of this [`Parameters<R, F>`].
    #[inline]
    pub fn key_switching_basis_powers(&self) -> &[F] {
        &self.key_switching_basis_powers
    }
}

impl<R: RandomRing, F: NTTField> Parameters<R, F> {
    /// Gets the lwe noise distribution.
    #[inline]
    pub fn lwe_noise_distribution(&self) -> <R as Random>::NormalDistribution {
        R::normal_distribution(0.0, self.lwe_noise_std_dev).unwrap()
    }
}

impl<R: Ring, F: RandomNTTField> Parameters<R, F> {
    /// Gets the rlwe noise distribution.
    #[inline]
    pub fn rlwe_noise_distribution(&self) -> <F as Random>::NormalDistribution {
        F::normal_distribution(0.0, self.rlwe_noise_std_dev).unwrap()
    }
}

/// Default Ring for Default Parameters
#[derive(Ring, Random)]
#[modulus = 1024]
pub struct DefaultRing100(u32);

/// Default Field for Default Parameters
#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 1073692673]
pub struct DefaultField100(u32);

/// Default Parameters
pub const CONST_DEFAULT_100_BITS_PARAMERTERS: ConstParameters<u32> = ConstParameters::<u32> {
    lwe_dimension: 512,
    lwe_modulus: 1024,
    lwe_noise_std_dev: 3.20,
    secret_key_type: SecretKeyType::Ternary,
    rlwe_dimension: 1024,
    rlwe_modulus: 1073692673,
    rlwe_noise_std_dev: 3.20,
    gadget_basis_bits: 6,
    key_switching_basis_bits: 3,
};

/// Default 100bits security Parameters
pub static DEFAULT_100_BITS_PARAMERTERS: Lazy<Parameters<DefaultRing100, DefaultField100>> =
    Lazy::new(|| {
        <Parameters<DefaultRing100, DefaultField100>>::from(CONST_DEFAULT_100_BITS_PARAMERTERS)
    });
