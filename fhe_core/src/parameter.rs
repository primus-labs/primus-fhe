use algebra::{
    derive::*, modulus::PowOf2Modulus, Basis, Field, FieldDiscreteGaussianSampler, NTTField,
};
use lattice::DiscreteGaussian;

use crate::{FHECoreError, LWEModulusType, SecretKeyType};

/// Parameters for LWE.
#[derive(Debug, Clone, Copy)]
pub struct LWEParameters {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: PowOf2Modulus<LWEModulusType>,
    /// The lwe noise error's standard deviation
    pub lwe_noise_std_dev: f64,
}

/// Use `RLWE` or `NTRU` to perform blind rotation.
#[derive(Debug, Clone, Copy)]
pub enum BlindRotationType {
    /// Use `RLWE` to perform blind rotation.
    RLWE,
    /// Use `NTRU` to perform blind rotation.
    NTRU,
}

/// Parameters for blind rotation.
#[derive(Debug, Clone, Copy)]
pub struct BlindRotationParameters<F: NTTField> {
    /// The dimension of the ring for rlwe and ntru, refers to **`N`** in the paper.
    pub ring_dimension: usize,
    /// The modulus of the ring for rlwe and ntru, refers to **`Q`** in the paper.
    pub ring_modulus: F::Value,
    /// The noise error's standard deviation for rlwe and ntru.
    pub ring_noise_std_dev: f64,
    /// Decompose basis for `Q` used for bootstrapping accumulator
    pub blind_rotation_basis: Basis<F>,
    /// Refers to **`2N/q`** in the paper.
    pub twice_ring_dimension_div_lwe_modulus: usize,
    /// Use `RLWE` or `NTRU` to perform blind rotation.
    pub blind_rotation_type: BlindRotationType,
}

/// Parameters for key switching.
#[derive(Debug, Clone, Copy)]
pub struct KeySwitchingParameters<F: NTTField> {
    /// Decompose basis for `Q` used for key switching.
    pub key_switching_basis: Basis<F>,
    /// The rlwe noise error's standard deviation for key switching.
    pub key_switching_std_dev: f64,
}

/// Parameters for FHE
#[derive(Debug, Clone, Copy)]
pub struct Parameters<F: NTTField> {
    secret_key_type: SecretKeyType,
    lwe_params: LWEParameters,
    blind_rotation_params: BlindRotationParameters<F>,
    key_switching_params: KeySwitchingParameters<F>,
}

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<Scalar> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: LWEModulusType,
    /// The lwe noise error's standard deviation
    pub lwe_noise_std_dev: f64,
    /// LWE Secret Key distribution Type
    pub secret_key_type: SecretKeyType,

    /// Use `RLWE` or `NTRU` to perform blind rotation.
    pub blind_rotation_type: BlindRotationType,

    /// Ring polynomial dimension, refers to **`N`** in the paper.
    pub ring_dimension: usize,
    /// Ring polynomial modulus, refers to **`Q`** in the paper.
    pub ring_modulus: Scalar,
    /// The ring noise error's standard deviation for rlwe and ntru
    pub ring_noise_std_dev: f64,

    /// Decompose basis for `Q` used for blind rotation accumulator
    pub blind_rotation_basis_bits: u32,

    /// Decompose basis for `Q` used for key switching.
    pub key_switching_basis_bits: u32,
    /// The rlwe noise error's standard deviation for key switching.
    pub key_switching_std_dev: f64,
}

impl<F: NTTField> Parameters<F> {
    /// Create a new Parameter instance.
    pub fn new(params: ConstParameters<F::Value>) -> Result<Self, FHECoreError> {
        let lwe_modulus = params.lwe_modulus;
        let ring_dimension = params.ring_dimension;
        let ring_modulus = params.ring_modulus;

        // N = 2^i
        if !ring_dimension.is_power_of_two() {
            return Err(FHECoreError::RingDimensionUnValid(ring_dimension));
        }

        // q|2N
        #[allow(clippy::unnecessary_fallible_conversions)]
        let lwe_modulus_u: usize = lwe_modulus.try_into().unwrap();
        let twice_ring_dimension_div_lwe_modulus = (ring_dimension << 1) / lwe_modulus_u;
        if twice_ring_dimension_div_lwe_modulus * lwe_modulus_u != (ring_dimension << 1) {
            return Err(FHECoreError::LweModulusRingDimensionNotCompatible {
                lwe_modulus: lwe_modulus_u,
                ring_dimension,
            });
        }

        // 2N|(Q-1)
        let t: u64 = ring_modulus.into();
        let ring_modulus_u = t.try_into().unwrap();
        let temp = (ring_modulus_u - 1) / (ring_dimension << 1);
        if temp * (ring_dimension << 1) != (ring_modulus_u - 1) {
            return Err(FHECoreError::RingModulusAndDimensionNotCompatible {
                ring_modulus: ring_modulus_u,
                ring_dimension,
            });
        }

        let lwe_params = LWEParameters {
            lwe_dimension: params.lwe_dimension,
            lwe_modulus: PowOf2Modulus::<LWEModulusType>::new(lwe_modulus),
            lwe_noise_std_dev: params.lwe_noise_std_dev,
        };

        let blind_rotation_params = BlindRotationParameters::<F> {
            ring_dimension,
            ring_modulus,
            ring_noise_std_dev: params.ring_noise_std_dev,
            blind_rotation_basis: Basis::<F>::new(params.blind_rotation_basis_bits),
            twice_ring_dimension_div_lwe_modulus,
            blind_rotation_type: params.blind_rotation_type,
        };

        let key_switching_params = KeySwitchingParameters::<F> {
            key_switching_basis: Basis::<F>::new(params.key_switching_basis_bits),
            key_switching_std_dev: params.key_switching_std_dev,
        };

        Ok(Self {
            secret_key_type: params.secret_key_type,
            lwe_params,
            blind_rotation_params,
            key_switching_params,
        })
    }

    /// Returns the lwe dimension of this [`Parameters<F>`], refers to **`n`** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_params.lwe_dimension
    }

    /// Returns the lwe modulus of this [`Parameters<F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus(&self) -> PowOf2Modulus<LWEModulusType> {
        self.lwe_params.lwe_modulus
    }

    /// Returns the lwe noise error's standard deviation of this [`Parameters<F>`].
    #[inline]
    pub fn lwe_noise_std_dev(&self) -> f64 {
        self.lwe_params.lwe_noise_std_dev
    }

    /// Returns the LWE Secret Key distribution Type of this [`Parameters<F>`].
    #[inline]
    pub fn secret_key_type(&self) -> SecretKeyType {
        self.secret_key_type
    }

    /// Returns the ring dimension of this [`Parameters<F>`], refers to **`N`** in the paper.
    #[inline]
    pub fn ring_dimension(&self) -> usize {
        self.blind_rotation_params.ring_dimension
    }

    /// Returns the ring modulus of this [`Parameters<F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn ring_modulus(&self) -> <F as Field>::Value {
        self.blind_rotation_params.ring_modulus
    }

    /// Returns the ring noise error's standard deviation of this [`Parameters<F>`].
    #[inline]
    pub fn ring_noise_std_dev(&self) -> f64 {
        self.blind_rotation_params.ring_noise_std_dev
    }

    /// Returns the twice ring dimension divides lwe modulus of this [`Parameters<F>`], refers to **`2N/q`** in the paper.
    #[inline]
    pub fn twice_ring_dimension_div_lwe_modulus(&self) -> usize {
        self.blind_rotation_params
            .twice_ring_dimension_div_lwe_modulus
    }

    /// Use `RLWE` or `NTRU` to perform blind rotation.
    #[inline]
    pub fn blind_rotation_type(&self) -> BlindRotationType {
        self.blind_rotation_params.blind_rotation_type
    }

    /// Returns the gadget basis of this [`Parameters<F>`],
    /// which acts as the decompose basis for `Q` used for bootstrapping accumulator.
    #[inline]
    pub fn blind_rotation_basis(&self) -> Basis<F> {
        self.blind_rotation_params.blind_rotation_basis
    }

    /// Returns the key switching basis of this [`Parameters<F>`],
    /// which acts as the decompose basis for `Q` used for key switching.
    #[inline]
    pub fn key_switching_basis(&self) -> Basis<F> {
        self.key_switching_params.key_switching_basis
    }

    /// Returns the key switching error's standard deviation of this [`Parameters<F>`].
    #[inline]
    pub fn key_switching_std_dev(&self) -> f64 {
        self.key_switching_params.key_switching_std_dev
    }

    /// Gets the lwe noise distribution.
    #[inline]
    pub fn lwe_noise_distribution(&self) -> DiscreteGaussian<LWEModulusType> {
        DiscreteGaussian::new(self.lwe_modulus().value(), 0.0, self.lwe_noise_std_dev()).unwrap()
    }

    /// Gets the ring noise distribution.
    #[inline]
    pub fn ring_noise_distribution(&self) -> FieldDiscreteGaussianSampler {
        FieldDiscreteGaussianSampler::new(0.0, self.ring_noise_std_dev()).unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution(&self) -> FieldDiscreteGaussianSampler {
        FieldDiscreteGaussianSampler::new(0.0, self.key_switching_std_dev()).unwrap()
    }
}

/// Default Field for Default Parameters
#[derive(Field, Prime, NTT)]
#[modulus = 132120577]
#[repr(transparent)]
pub struct DefaultFieldU32(u32);
