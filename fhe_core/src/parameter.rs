use algebra::{
    derive::*, modulus::PowOf2Modulus, Basis, BinomialExtensionField, BinomiallyExtendable, Field,
    FieldDiscreteGaussianSampler, HasTwoAdicBionmialExtension, NTTField, Packable,
};
use lattice::DiscreteGaussian;

use crate::{
    FHECoreError, LWEModulusType, ModulusSwitchRoundMethod, RingSecretKeyType, SecretKeyType,
};

/// The steps after blind rotation.
#[derive(Debug, Default, Clone, Copy)]
pub enum StepsAfterBR {
    /// Modulus Switch, Key Switch and Modulus Switch
    MsKsMs,
    /// Key Switch and Modulus Switch
    #[default]
    KsMs,
    /// Modulus Switch
    Ms,
}

/// Parameters for LWE.
#[derive(Debug, Clone, Copy)]
pub struct LWEParameters<C: LWEModulusType> {
    /// **LWE** vector dimension, refers to **n** in the paper.
    pub dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    pub plain_modulus: u64,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub cipher_modulus: PowOf2Modulus<C>,
    /// **LWE** cipher modulus value, refers to **q** in the paper.
    pub cipher_modulus_value: C,
    /// The distribution type of the LWE Secret Key.
    pub secret_key_type: SecretKeyType,
    /// **LWE** noise error's standard deviation.
    pub noise_standard_deviation: f64,
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
pub struct BlindRotationParameters<Q: NTTField> {
    /// The dimension of the ring for rlwe or ntru, refers to **N** in the paper.
    pub dimension: usize,
    /// The modulus of the ring for rlwe or ntru, refers to **Q** in the paper.
    pub modulus: Q::Value,
    /// The noise error's standard deviation for rlwe or ntru.
    pub noise_standard_deviation: f64,
    /// The distribution type of the Ring Secret Key.
    pub secret_key_type: RingSecretKeyType,
    /// Decompose basis for `Q` used for bootstrapping accumulator.
    pub basis: Basis<Q>,
    /// Refers to **2N/q** in the paper.
    pub twice_ring_dimension_div_lwe_modulus: usize,
    /// Use `RLWE` or `NTRU` to perform blind rotation.
    pub blind_rotation_type: BlindRotationType,
}

/// Parameters for key switching.
#[derive(Debug, Clone, Copy)]
pub struct KeySwitchingParameters<Q: NTTField, Qks: NTTField> {
    /// The modulus of the ring for rlwe, refers to **Qks** in the paper.
    #[allow(dead_code)]
    pub modulus: Qks::Value,
    /// Decompose basis for `Qks` used for key switching.
    pub basis_q: Basis<Q>,
    /// Decompose basis for `Qks` used for key switching.
    pub basis_qks: Basis<Qks>,
    /// The rlwe noise error's standard deviation for key switching.
    pub noise_standard_deviation: f64,
}

/// Parameters for modulus switching.
#[derive(Debug, Clone, Copy)]
pub struct ModulusSwitchParameters {
    /// Modulus Switch round method.
    pub round_method: ModulusSwitchRoundMethod,
}

/// Parameters for the fully homomorphic encryption scheme.
#[derive(Debug, Clone, Copy)]
pub struct Parameters<C: LWEModulusType, Q: NTTField, Qks: NTTField> {
    lwe_params: LWEParameters<C>,
    blind_rotation_params: BlindRotationParameters<Q>,
    steps_after_blind_rotation: StepsAfterBR,
    key_switching_params: KeySwitchingParameters<Q, Qks>,
    modulus_switch_params: ModulusSwitchParameters,
}

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<C: LWEModulusType, Q, Qks> {
    /// **LWE** vector dimension, refers to **n** in the paper.
    pub lwe_dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    pub lwe_plain_modulus: C,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub lwe_cipher_modulus: C,
    /// The **LWE** noise error's standard deviation.
    pub lwe_noise_standard_deviation: f64,
    /// **LWE** Secret Key distribution Type.
    pub secret_key_type: SecretKeyType,

    /// Use `RLWE` or `NTRU` to perform blind rotation.
    pub blind_rotation_type: BlindRotationType,

    /// **Ring** polynomial dimension, refers to **N** in the paper.
    pub ring_dimension: usize,
    /// **Ring** polynomial modulus, refers to **Q** in the paper.
    pub ring_modulus: Q,
    /// The **Ring** noise error's standard deviation for **rlwe** or **ntru**.
    pub ring_noise_standard_deviation: f64,
    /// The distribution type of the **Ring** Secret Key.
    pub ring_secret_key_type: RingSecretKeyType,

    /// Decompose basis for `Q` used for blind rotation accumulator.
    pub blind_rotation_basis_bits: u32,

    /// The steps after blind rotarion.
    pub steps_after_blind_rotation: StepsAfterBR,

    /// Polynomial modulus for **key swithching**, refers to **Qks** in the paper.
    pub key_switching_modulus: Qks,
    /// Decompose basis for `Qks` used for key switching.
    pub key_switching_basis_bits: u32,
    /// The **rlwe** noise error's standard deviation for key switching.
    pub key_switching_standard_deviation: f64,

    /// Modulus Switch round method.
    pub modulus_switcing_round_method: ModulusSwitchRoundMethod,
}

impl<C: LWEModulusType, Q: NTTField, Qks: NTTField> Parameters<C, Q, Qks> {
    /// Create a new Parameter instance.
    pub fn new(params: ConstParameters<C, Q::Value, Qks::Value>) -> Result<Self, FHECoreError> {
        let lwe_dimension = params.lwe_dimension;
        let lwe_cipher_modulus = params.lwe_cipher_modulus;
        let ring_dimension = params.ring_dimension;
        let ring_modulus = params.ring_modulus;
        let key_switching_modulus = params.key_switching_modulus;

        let secret_key_type = params.secret_key_type;
        let ring_secret_key_type = params.ring_secret_key_type;
        let steps_after_blind_rotation = params.steps_after_blind_rotation;
        let blind_rotation_type = params.blind_rotation_type;

        match steps_after_blind_rotation {
            StepsAfterBR::MsKsMs => {
                let ring_modulus = Into::<u64>::into(ring_modulus);
                let key_switching_modulus = Into::<u64>::into(key_switching_modulus);
                if ring_modulus < key_switching_modulus {
                    return Err(FHECoreError::StepsParametersNotCompatible);
                }
            }
            StepsAfterBR::KsMs => {
                let ring_modulus = Into::<u64>::into(ring_modulus);
                let key_switching_modulus = Into::<u64>::into(key_switching_modulus);
                if ring_modulus != key_switching_modulus {
                    return Err(FHECoreError::StepsParametersNotCompatible);
                }
            }
            StepsAfterBR::Ms => {
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
        }

        // N = 2^i
        if !ring_dimension.is_power_of_two() {
            return Err(FHECoreError::RingDimensionUnValid(ring_dimension));
        }

        // q|2N
        let lwe_modulus_u: usize = lwe_cipher_modulus.try_into().ok().unwrap();
        let twice_ring_dimension_div_lwe_modulus = (ring_dimension << 1) / lwe_modulus_u;
        if twice_ring_dimension_div_lwe_modulus * lwe_modulus_u != (ring_dimension << 1) {
            return Err(FHECoreError::LweModulusRingDimensionNotCompatible {
                lwe_modulus: lwe_modulus_u,
                ring_dimension,
            });
        }

        // 2N|(Q-1)
        let ring_modulus_u = Into::<u64>::into(ring_modulus).try_into().unwrap();
        let temp = (ring_modulus_u - 1) / (ring_dimension << 1);
        if temp * (ring_dimension << 1) != (ring_modulus_u - 1) {
            return Err(FHECoreError::RingModulusAndDimensionNotCompatible {
                coeff_modulus: ring_modulus_u,
                ring_dimension,
            });
        }

        let t: u64 = params.lwe_plain_modulus.as_into();
        let q: u64 = lwe_cipher_modulus.as_into();
        assert!(t <= q);
        assert!(t.is_power_of_two() && q.is_power_of_two());
        let lwe_params = LWEParameters {
            dimension: lwe_dimension,
            cipher_modulus_value: lwe_cipher_modulus,
            cipher_modulus: lwe_cipher_modulus.to_power_of_2_modulus(),
            noise_standard_deviation: params.lwe_noise_standard_deviation,
            plain_modulus: t,
            secret_key_type,
        };

        let blind_rotation_params = BlindRotationParameters::<Q> {
            dimension: ring_dimension,
            modulus: ring_modulus,
            noise_standard_deviation: params.ring_noise_standard_deviation,
            basis: Basis::<Q>::new(params.blind_rotation_basis_bits),
            twice_ring_dimension_div_lwe_modulus,
            blind_rotation_type,
            secret_key_type: ring_secret_key_type,
        };

        let key_switching_params = KeySwitchingParameters::<Q, Qks> {
            modulus: key_switching_modulus,
            basis_q: Basis::<Q>::new(params.key_switching_basis_bits),
            basis_qks: Basis::<Qks>::new(params.key_switching_basis_bits),
            noise_standard_deviation: params.key_switching_standard_deviation,
        };

        let modulus_switch_params = ModulusSwitchParameters {
            round_method: params.modulus_switcing_round_method,
        };

        Ok(Self {
            steps_after_blind_rotation,
            lwe_params,
            blind_rotation_params,
            key_switching_params,
            modulus_switch_params,
        })
    }

    /// Returns the LWE dimension of this [`Parameters<C, Q, Qks>`], refers to **n** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_params.dimension
    }

    /// Returns the LWE message modulus of this [`Parameters<C, Q, Qks>`], refers to **t** in the paper.
    #[inline]
    pub fn lwe_plain_modulus(&self) -> u64 {
        self.lwe_params.plain_modulus
    }

    /// Returns the LWE modulus of this [`Parameters<C, Q, Qks>`], refers to **q** in the paper.
    #[inline]
    pub fn lwe_cipher_modulus(&self) -> PowOf2Modulus<C> {
        self.lwe_params.cipher_modulus
    }

    /// Returns the LWE cipher modulus of this [`Parameters<C, Q, Qks>`], refers to **q** in the paper.
    #[inline]
    pub fn lwe_cipher_modulus_value(&self) -> C {
        self.lwe_params.cipher_modulus_value
    }

    /// Returns the LWE noise error's standard deviation of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn lwe_noise_standard_deviation(&self) -> f64 {
        self.lwe_params.noise_standard_deviation
    }

    /// Returns the LWE Secret Key distribution Type of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn secret_key_type(&self) -> SecretKeyType {
        self.lwe_params.secret_key_type
    }

    /// Returns the ring dimension of this [`Parameters<C, Q, Qks>`], refers to **N** in the paper.
    #[inline]
    pub fn ring_dimension(&self) -> usize {
        self.blind_rotation_params.dimension
    }

    /// Returns the ring modulus of this [`Parameters<C, Q, Qks>`], refers to **Q** in the paper.
    #[inline]
    pub fn ring_modulus(&self) -> <Q as Field>::Value {
        self.blind_rotation_params.modulus
    }

    /// Returns the ring noise error's standard deviation of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn ring_noise_standard_deviation(&self) -> f64 {
        self.blind_rotation_params.noise_standard_deviation
    }

    /// Returns the twice ring dimension divides lwe modulus of this [`Parameters<C, Q, Qks>`], refers to **2N/q** in the paper.
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

    /// Returns the gadget basis of this [`Parameters<C, Q, Qks>`],
    /// which acts as the decompose basis for `Q` used for bootstrapping accumulator.
    #[inline]
    pub fn blind_rotation_basis(&self) -> Basis<Q> {
        self.blind_rotation_params.basis
    }

    /// Returns the key switching basis of this [`Parameters<C, Q, Qks>`],
    /// which acts as the decompose basis for `Q` used for key switching.
    #[inline]
    pub fn key_switching_basis_q(&self) -> Basis<Q> {
        self.key_switching_params.basis_q
    }

    /// Returns the key switching basis of this [`Parameters<C, Q, Qks>`],
    /// which acts as the decompose basis for `Qks` used for key switching.
    #[inline]
    pub fn key_switching_basis_qks(&self) -> Basis<Qks> {
        self.key_switching_params.basis_qks
    }

    /// Returns the key switching error's standard deviation of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn key_switching_noise_standard_deviation(&self) -> f64 {
        self.key_switching_params.noise_standard_deviation
    }

    /// Gets the lwe noise distribution.
    #[inline]
    pub fn lwe_noise_distribution(&self) -> DiscreteGaussian<C> {
        DiscreteGaussian::new(
            self.lwe_cipher_modulus().value(),
            0.0,
            self.lwe_noise_standard_deviation(),
        )
        .unwrap()
    }

    /// Gets the ring noise distribution.
    #[inline]
    pub fn ring_noise_distribution(&self) -> FieldDiscreteGaussianSampler {
        FieldDiscreteGaussianSampler::new(0.0, self.ring_noise_standard_deviation()).unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution(&self) -> FieldDiscreteGaussianSampler {
        FieldDiscreteGaussianSampler::new(0.0, self.key_switching_noise_standard_deviation())
            .unwrap()
    }

    /// Returns the ring secret key type of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn ring_secret_key_type(&self) -> RingSecretKeyType {
        self.blind_rotation_params.secret_key_type
    }

    /// Returns the steps after blind rotation of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn steps_after_blind_rotation(&self) -> StepsAfterBR {
        self.steps_after_blind_rotation
    }

    /// Returns the modulus switch round method of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn modulus_switch_round_method(&self) -> ModulusSwitchRoundMethod {
        self.modulus_switch_params.round_method
    }

    /// Returns the LWE parameters of this [`Parameters<C, Q, Qks>`].
    #[inline]
    pub fn lwe_params(&self) -> LWEParameters<C> {
        self.lwe_params
    }
}

/// Default Field for Default Parameters
#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
#[repr(transparent)]
pub struct DefaultFieldU32(u32);

/// Default Field for Default Parameters
#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 15361]
#[repr(transparent)]
pub struct DefaultQks(u32);

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
