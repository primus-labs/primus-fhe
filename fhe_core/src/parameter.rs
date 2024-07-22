use std::marker::PhantomData;

use algebra::{
    derive::*, modulus::PowOf2Modulus, Basis, BinomialExtensionField, BinomiallyExtendable, Field,
    FieldDiscreteGaussianSampler, HasTwoAdicBionmialExtension, NTTField, Packable,
};
use lattice::DiscreteGaussian;

use crate::{
    Code, FHECoreError, LWECipherValueContainer, LWEPlainContainer, ModulusSwitchRoundMethod,
    RingSecretKeyType, SecretKeyType,
};

/// The steps after blind rotarion.
#[derive(Debug, Default, Clone, Copy)]
pub enum StepsAfterBR {
    /// Key Switch and Modulus Switch
    #[default]
    KsMs,
    /// Modulus Switch
    Ms,
}

/// Parameters for LWE.
#[derive(Debug, Clone, Copy)]
pub struct LWEParameters<M: LWEPlainContainer<C>, C: LWECipherValueContainer> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: PowOf2Modulus<C>,
    /// The lwe noise error's standard deviation
    pub lwe_noise_std_dev: f64,
    /// LWE `encode` and `decode`.
    pub code: Code<M, C>,
}

/// Use `RLWE` or `NTRU` to perform blind rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Parameters for modulus switching.
#[derive(Debug, Clone, Copy)]
pub struct ModulusSwitchParameters {
    pub round_method: ModulusSwitchRoundMethod,
}

/// Parameters for FHE
#[derive(Debug, Clone, Copy)]
pub struct Parameters<M: LWEPlainContainer<C>, C: LWECipherValueContainer, F: NTTField> {
    secret_key_type: SecretKeyType,
    ring_secret_key_type: RingSecretKeyType,
    steps_after_blind_rotation: StepsAfterBR,
    lwe_params: LWEParameters<M, C>,
    blind_rotation_params: BlindRotationParameters<F>,
    key_switching_params: KeySwitchingParameters<F>,
    modulus_switch_params: ModulusSwitchParameters,
}

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<M: LWEPlainContainer<C>, C: LWECipherValueContainer, FieldContainer> {
    /// LWE vector dimension, refers to **`n`** in the paper.
    pub lwe_dimension: usize,
    /// LWE cipher modulus, refers to **`q`** in the paper.
    pub lwe_modulus: C,
    /// LWE message space(not contain padding).
    pub real_message_size: C,
    /// LWE message space(may contain padding).
    pub padding_message_size: C,
    /// The lwe noise error's standard deviation
    pub lwe_noise_std_dev: f64,
    /// LWE Secret Key distribution Type
    pub secret_key_type: SecretKeyType,

    /// Use `RLWE` or `NTRU` to perform blind rotation.
    pub blind_rotation_type: BlindRotationType,

    /// Ring polynomial dimension, refers to **`N`** in the paper.
    pub ring_dimension: usize,
    /// Ring polynomial modulus, refers to **`Q`** in the paper.
    pub ring_modulus: FieldContainer,
    /// The ring noise error's standard deviation for rlwe and ntru
    pub ring_noise_std_dev: f64,
    /// The distribution type of the Ring Secret Key
    pub ring_secret_key_type: RingSecretKeyType,

    /// Decompose basis for `Q` used for blind rotation accumulator
    pub blind_rotation_basis_bits: u32,

    /// The steps after blind rotarion.
    pub steps_after_blind_rotation: StepsAfterBR,

    /// Decompose basis for `Q` used for key switching.
    pub key_switching_basis_bits: u32,
    /// The rlwe noise error's standard deviation for key switching.
    pub key_switching_std_dev: f64,

    /// Modulus Switch round method.
    pub modulus_switcing_round_method: ModulusSwitchRoundMethod,

    /// phantom
    pub phantom: PhantomData<M>,
}

impl<M: LWEPlainContainer<C>, C: LWECipherValueContainer, F: NTTField> Parameters<M, C, F> {
    /// Create a new Parameter instance.
    pub fn new(params: ConstParameters<M, C, F::Value>) -> Result<Self, FHECoreError> {
        let lwe_dimension = params.lwe_dimension;
        let lwe_modulus = params.lwe_modulus;
        let ring_dimension = params.ring_dimension;
        let ring_modulus = params.ring_modulus;

        let secret_key_type = params.secret_key_type;
        let ring_secret_key_type = params.ring_secret_key_type;
        let steps_after_blind_rotation = params.steps_after_blind_rotation;
        let blind_rotation_type = params.blind_rotation_type;

        if let StepsAfterBR::Ms = steps_after_blind_rotation {
            // Currently, only support RLWE Blind Rotation for this mode
            if !(blind_rotation_type == BlindRotationType::RLWE
                && lwe_dimension == ring_dimension
                && ((secret_key_type == SecretKeyType::Binary
                    && ring_secret_key_type == RingSecretKeyType::Binary)
                    || (secret_key_type == SecretKeyType::Ternary
                        && ring_secret_key_type == RingSecretKeyType::Ternary)))
            {
                return Err(FHECoreError::StepsParametersNotCompatible);
            }
        }

        // N = 2^i
        if !ring_dimension.is_power_of_two() {
            return Err(FHECoreError::RingDimensionUnValid(ring_dimension));
        }

        // q|2N
        let lwe_modulus_u: usize = lwe_modulus.try_into().ok().unwrap();
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
                coeff_modulus: ring_modulus_u,
                ring_dimension,
            });
        }

        let lwe_params = LWEParameters {
            lwe_dimension: params.lwe_dimension,
            lwe_modulus: lwe_modulus.to_power_of_2_modulus(),
            lwe_noise_std_dev: params.lwe_noise_std_dev,
            code: Code::new(
                params.real_message_size,
                params.padding_message_size,
                lwe_modulus,
            ),
        };

        let blind_rotation_params = BlindRotationParameters::<F> {
            ring_dimension,
            ring_modulus,
            ring_noise_std_dev: params.ring_noise_std_dev,
            blind_rotation_basis: Basis::<F>::new(params.blind_rotation_basis_bits),
            twice_ring_dimension_div_lwe_modulus,
            blind_rotation_type,
        };

        let key_switching_params = KeySwitchingParameters::<F> {
            key_switching_basis: Basis::<F>::new(params.key_switching_basis_bits),
            key_switching_std_dev: params.key_switching_std_dev,
        };

        let modulus_switch_params = ModulusSwitchParameters {
            round_method: params.modulus_switcing_round_method,
        };

        Ok(Self {
            secret_key_type,
            ring_secret_key_type,
            steps_after_blind_rotation,
            lwe_params,
            blind_rotation_params,
            key_switching_params,
            modulus_switch_params,
        })
    }

    /// Returns the lwe dimension of this [`Parameters<F>`], refers to **`n`** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_params.lwe_dimension
    }

    /// Returns the lwe modulus of this [`Parameters<F>`], refers to **`q`** in the paper.
    #[inline]
    pub fn lwe_modulus(&self) -> PowOf2Modulus<C> {
        self.lwe_params.lwe_modulus
    }

    /// Returns the lwe noise error's standard deviation of this [`Parameters<F>`].
    #[inline]
    pub fn lwe_noise_std_dev(&self) -> f64 {
        self.lwe_params.lwe_noise_std_dev
    }

    /// Returns the lwe coder of this [`Parameters<F>`].
    #[inline]
    pub fn lwe_coder(&self) -> Code<M, C> {
        self.lwe_params.code
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
    pub fn lwe_noise_distribution(&self) -> DiscreteGaussian<C> {
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

    /// Returns the ring secret key type of this [`Parameters<F>`].
    #[inline]
    pub fn ring_secret_key_type(&self) -> RingSecretKeyType {
        self.ring_secret_key_type
    }

    /// Returns the steps after blind rotation of this [`Parameters<F>`].
    #[inline]
    pub fn steps_after_blind_rotation(&self) -> StepsAfterBR {
        self.steps_after_blind_rotation
    }

    /// Returns the modulus switch round method of this [`Parameters<F>`].
    #[inline]
    pub fn modulus_switch_round_method(&self) -> ModulusSwitchRoundMethod {
        self.modulus_switch_params.round_method
    }
}

/// Default Field for Default Parameters
#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
#[repr(transparent)]
pub struct DefaultFieldU32(u32);

impl BinomiallyExtendable<4> for DefaultFieldU32 {
    // Verifiable in Sage with
    // `R.<x> = GF(p)[]; assert (x^4 - 5).is_irreducible()`.
    fn w() -> Self {
        Self::new(5)
    }

    fn dth_root() -> Self {
        Self::new(130039810)
    }

    fn ext_generator() -> [Self; 4] {
        std::unimplemented!()
    }
}

impl HasTwoAdicBionmialExtension<4> for DefaultFieldU32 {
    const EXT_TWO_ADICITY: usize = 1;

    fn ext_two_adic_generator(_bits: usize) -> [Self; 4] {
        std::unimplemented!()
    }
}

impl Packable for DefaultFieldU32 {}

/// Default extension field of default 32-bit field.
pub type DefaultExtendsionFieldU32x4 = BinomialExtensionField<DefaultFieldU32, 4>;

mod tests {
    #[test]
    fn default_extension_field() {
        use crate::{DefaultExtendsionFieldU32x4, DefaultFieldU32};
        use algebra::{AbstractExtensionField, FieldUniformSampler};
        use num_traits::{Inv, One};
        use rand::distributions::Distribution;
        use rand::thread_rng;

        let mut rng = thread_rng();

        let a = DefaultExtendsionFieldU32x4::random(&mut rng);

        let b = DefaultExtendsionFieldU32x4::random(&mut rng);

        let c: DefaultFieldU32 = FieldUniformSampler::new().sample(&mut rng);
        let c_ext = DefaultExtendsionFieldU32x4::from_base(c);

        assert_eq!(a + b, b + a);
        assert_eq!(a + c, c_ext + a);
        assert_eq!(a + c, c_ext + a);
        assert_eq!(a - c, -(c_ext - a));
        assert_eq!((a / b) * b, a);

        assert_eq!(a * b, b * a);
        assert_eq!(a * c, a * c_ext);

        let a_inv = a.inv();

        assert_eq!(a * a_inv, DefaultExtendsionFieldU32x4::one());
    }
}
