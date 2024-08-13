use algebra::{
    derive::*, modulus::PowOf2Modulus, Basis, BinomialExtensionField, BinomiallyExtendable, Field,
    FieldDiscreteGaussianSampler, HasTwoAdicBionmialExtension, NTTField, Packable,
};
use lattice::DiscreteGaussian;

use crate::{
    FHECoreError, LWEModulusType, LWESecretKeyType, ModulusSwitchRoundMethod, RingSecretKeyType,
};

/// The steps of whole bootstrapping.
#[derive(Debug, Default, Clone, Copy)]
pub enum Steps {
    /// Modulus Switch -> Blind Rotation -> Modulus Switch -> Key Switch.
    ///
    /// ### Case: q >= 2N, 2N|q
    ///
    /// (n, q) -> (n, 2N) -> (N, Q) -> (N, q) -> (n, q)
    BrMsKs,
    /// Blind Rotation -> Key Switch -> Modulus Switch.
    ///
    /// ### Case: q <= 2N, q|2N
    ///
    /// (n, q) -> (N, Q) -> (n, Q) -> (n, q)
    #[default]
    BrKsMs,
    /// Blind Rotation -> Modulus Switch.
    ///
    /// ### Case: n = N
    ///
    /// (n, q) -> (N, Q) -> (n, q)
    BrMs,
}

/// The relation between `q` and `2N`.
#[derive(Debug, Clone, Copy)]
pub enum RelationOfqAnd2N {
    /// q > 2N, 2N|q
    Gt,
    /// q < 2N, q|2N
    Lt {
        /// 2N/q
        twice_ring_dimension_div_lwe_modulus: usize,
    },
    /// q = 2N
    Eq,
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
    pub secret_key_type: LWESecretKeyType,
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
    /// Use `RLWE` or `NTRU` to perform blind rotation.
    pub blind_rotation_type: BlindRotationType,
}

/// Parameters for key switching.
#[derive(Debug, Clone, Copy)]
pub struct KeySwitchingParameters {
    /// Decompose basis for `Q` or `q` used for key switching.
    pub basis_bits: u32,
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
#[allow(non_snake_case)]
pub struct Parameters<C: LWEModulusType, Q: NTTField> {
    lwe_params: LWEParameters<C>,
    blind_rotation_params: BlindRotationParameters<Q>,
    key_switching_params: KeySwitchingParameters,
    modulus_switch_params: ModulusSwitchParameters,
    relation_of_q_and_2N: RelationOfqAnd2N,
    steps: Steps,
}

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<C: LWEModulusType, Q> {
    /// **LWE** vector dimension, refers to **n** in the paper.
    pub lwe_dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    pub lwe_plain_modulus: C,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub lwe_cipher_modulus: C,
    /// The **LWE** noise error's standard deviation.
    pub lwe_noise_standard_deviation: f64,
    /// **LWE** Secret Key distribution Type.
    pub lwe_secret_key_type: LWESecretKeyType,

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

    /// Decompose basis' bits for `Q` used for blind rotation accumulator.
    pub blind_rotation_basis_bits: u32,

    /// The steps of whole bootstrapping.
    pub steps: Steps,

    /// Decompose basis' bits for `Q` or `q` used for key switching.
    pub key_switching_basis_bits: u32,
    /// The noise error's standard deviation for key switching **rlwe** or **lwe**.
    pub key_switching_standard_deviation: f64,

    /// Modulus Switch round method.
    pub modulus_switcing_round_method: ModulusSwitchRoundMethod,
}

impl<C: LWEModulusType, Q: NTTField> Parameters<C, Q> {
    /// Create a new Parameter instance.
    pub fn new(params: ConstParameters<C, Q::Value>) -> Result<Self, FHECoreError> {
        let lwe_dimension = params.lwe_dimension;
        let lwe_cipher_modulus = params.lwe_cipher_modulus;
        let ring_dimension = params.ring_dimension;
        let ring_modulus = params.ring_modulus;

        let steps = params.steps;
        let secret_key_type = params.lwe_secret_key_type;
        let ring_secret_key_type = params.ring_secret_key_type;
        let blind_rotation_type = params.blind_rotation_type;

        let q: usize = lwe_cipher_modulus.try_into().ok().unwrap();
        let twice_ring_dimension = ring_dimension << 1;
        assert!(twice_ring_dimension != 0, "Ring dimension is too large!");

        let relation = if q < twice_ring_dimension {
            let twice_ring_dimension_div_lwe_modulus = twice_ring_dimension / q;
            if twice_ring_dimension_div_lwe_modulus * q != twice_ring_dimension {
                return Err(FHECoreError::LweModulusRingDimensionNotCompatible {
                    lwe_modulus: q,
                    ring_dimension,
                });
            }
            RelationOfqAnd2N::Lt {
                twice_ring_dimension_div_lwe_modulus,
            }
        } else if q == twice_ring_dimension {
            RelationOfqAnd2N::Eq
        } else {
            let lwe_modulus_div_twice_ring_dimension = q / twice_ring_dimension;
            if lwe_modulus_div_twice_ring_dimension * twice_ring_dimension != q {
                return Err(FHECoreError::LweModulusRingDimensionNotCompatible {
                    lwe_modulus: q,
                    ring_dimension,
                });
            }
            RelationOfqAnd2N::Gt
        };

        match steps {
            Steps::BrMsKs => {}
            Steps::BrKsMs => {}
            Steps::BrMs => {
                // Currently, only support RLWE Blind Rotation for this mode
                if !(blind_rotation_type == BlindRotationType::RLWE
                    && lwe_dimension == ring_dimension
                    && ((secret_key_type == LWESecretKeyType::Binary
                        && ring_secret_key_type == RingSecretKeyType::Binary)
                        || (secret_key_type == LWESecretKeyType::Ternary
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

        // 2N|(Q-1)
        let ring_modulus_u = Into::<u64>::into(ring_modulus).try_into().unwrap();
        let factor = (ring_modulus_u - 1) / (ring_dimension << 1);
        if factor * (ring_dimension << 1) != (ring_modulus_u - 1) {
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
            blind_rotation_type,
            secret_key_type: ring_secret_key_type,
        };

        let key_switching_params = KeySwitchingParameters {
            basis_bits: params.key_switching_basis_bits,
            noise_standard_deviation: params.key_switching_standard_deviation,
        };

        let modulus_switch_params = ModulusSwitchParameters {
            round_method: params.modulus_switcing_round_method,
        };

        Ok(Self {
            lwe_params,
            blind_rotation_params,
            key_switching_params,
            modulus_switch_params,
            steps,
            relation_of_q_and_2N: relation,
        })
    }

    /// Returns the LWE dimension of this [`Parameters<C, Q>`], refers to **n** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_params.dimension
    }

    /// Returns the LWE message modulus of this [`Parameters<C, Q>`], refers to **t** in the paper.
    #[inline]
    pub fn lwe_plain_modulus(&self) -> u64 {
        self.lwe_params.plain_modulus
    }

    /// Returns the LWE modulus of this [`Parameters<C, Q>`], refers to **q** in the paper.
    #[inline]
    pub fn lwe_cipher_modulus(&self) -> PowOf2Modulus<C> {
        self.lwe_params.cipher_modulus
    }

    /// Returns the LWE cipher modulus of this [`Parameters<C, Q>`], refers to **q** in the paper.
    #[inline]
    pub fn lwe_cipher_modulus_value(&self) -> C {
        self.lwe_params.cipher_modulus_value
    }

    /// Returns the LWE noise error's standard deviation of this [`Parameters<C, Q>`].
    #[inline]
    pub fn lwe_noise_standard_deviation(&self) -> f64 {
        self.lwe_params.noise_standard_deviation
    }

    /// Returns the LWE Secret Key distribution Type of this [`Parameters<C, Q>`].
    #[inline]
    pub fn lwe_secret_key_type(&self) -> LWESecretKeyType {
        self.lwe_params.secret_key_type
    }

    /// Returns the ring dimension of this [`Parameters<C, Q>`], refers to **N** in the paper.
    #[inline]
    pub fn ring_dimension(&self) -> usize {
        self.blind_rotation_params.dimension
    }

    /// Returns the ring modulus of this [`Parameters<C, Q>`], refers to **Q** in the paper.
    #[inline]
    pub fn ring_modulus(&self) -> <Q as Field>::Value {
        self.blind_rotation_params.modulus
    }

    /// Returns the ring noise error's standard deviation of this [`Parameters<C, Q>`].
    #[inline]
    pub fn ring_noise_standard_deviation(&self) -> f64 {
        self.blind_rotation_params.noise_standard_deviation
    }

    /// Use `RLWE` or `NTRU` to perform blind rotation.
    #[inline]
    pub fn blind_rotation_type(&self) -> BlindRotationType {
        self.blind_rotation_params.blind_rotation_type
    }

    /// Returns the gadget basis of this [`Parameters<C, Q>`],
    /// which acts as the decompose basis for `Q` used for bootstrapping accumulator.
    #[inline]
    pub fn blind_rotation_basis(&self) -> Basis<Q> {
        self.blind_rotation_params.basis
    }

    /// Returns the key switching basis' bits of this [`Parameters<C, Q>`],
    /// which acts as the decompose basis for `Q` or `q` used for key switching.
    #[inline]
    pub fn key_switching_basis_bits(&self) -> u32 {
        self.key_switching_params.basis_bits
    }

    /// Returns the key switching error's standard deviation of this [`Parameters<C, Q>`].
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
    pub fn key_switching_noise_distribution_for_ring(&self) -> FieldDiscreteGaussianSampler {
        FieldDiscreteGaussianSampler::new(0.0, self.key_switching_noise_standard_deviation())
            .unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution_for_lwe(&self) -> DiscreteGaussian<C> {
        DiscreteGaussian::new(
            self.lwe_cipher_modulus().value(),
            0.0,
            self.lwe_noise_standard_deviation(),
        )
        .unwrap()
    }

    /// Returns the ring secret key type of this [`Parameters<C, Q>`].
    #[inline]
    pub fn ring_secret_key_type(&self) -> RingSecretKeyType {
        self.blind_rotation_params.secret_key_type
    }

    /// Returns the steps of whole bootstrapping of this [`Parameters<C, Q>`].
    #[inline]
    pub fn steps(&self) -> Steps {
        self.steps
    }

    /// Returns the modulus switch round method of this [`Parameters<C, Q>`].
    #[inline]
    pub fn modulus_switch_round_method(&self) -> ModulusSwitchRoundMethod {
        self.modulus_switch_params.round_method
    }

    /// Returns the LWE parameters of this [`Parameters<C, Q>`].
    #[inline]
    pub fn lwe_params(&self) -> LWEParameters<C> {
        self.lwe_params
    }

    /// Returns the relaton of `q` and `2N` of this [`Parameters<C, Q>`].
    pub fn relation_of_q_and_2_n(&self) -> RelationOfqAnd2N {
        self.relation_of_q_and_2N
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
