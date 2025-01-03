//! The parameters of the fully homomorphic encryption scheme.

use algebra::decompose::NonPowOf2ApproxSignedBasis;
use algebra::integer::Bits;
use algebra::random::DiscreteGaussian;
use algebra::Field;
use algebra::{integer::UnsignedInteger, NttField};
use fhe_core::{FHECoreError, GadgetRlweParameters as BlindRotationParameters, ModulusValue};
use fhe_core::{KeySwitchingParameters, LweParameters, LweSecretKeyType, RingSecretKeyType};

mod constants;
mod steps;

pub use constants::*;
pub use steps::Steps;

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters<C: UnsignedInteger, Q> {
    /// **LWE** vector dimension, refers to **n** in the paper.
    pub lwe_dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    pub lwe_plain_modulus: C,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub lwe_cipher_modulus: ModulusValue<C>,
    /// The **LWE** noise error's standard deviation.
    pub lwe_noise_standard_deviation: f64,
    /// **LWE** Secret Key distribution Type.
    pub lwe_secret_key_type: LweSecretKeyType,

    /// **Ring** polynomial dimension, refers to **N** in the paper.
    pub ring_dimension: usize,
    /// **Ring** polynomial modulus, refers to **Q** in the paper.
    pub ring_modulus: Q,
    /// The **Ring** noise error's standard deviation for **rlwe**.
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
}

/// Parameters for the boolean fully homomorphic encryption scheme.
#[derive(Debug)]
pub struct BooleanFheParameters<C: UnsignedInteger, Q: NttField> {
    lwe_params: LweParameters<C>,
    blind_rotation_params: BlindRotationParameters<Q>,
    key_switching_params: KeySwitchingParameters,
    steps: Steps,
}

impl<C: UnsignedInteger, Q: NttField> Clone for BooleanFheParameters<C, Q> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: UnsignedInteger, Q: NttField> Copy for BooleanFheParameters<C, Q> {}

impl<C: UnsignedInteger, Q: NttField> BooleanFheParameters<C, Q> {
    /// Create a new Parameter instance.
    pub fn new(params: ConstParameters<C, <Q as Field>::ValueT>) -> Result<Self, FHECoreError> {
        let lwe_dimension = params.lwe_dimension;
        let lwe_cipher_modulus = params.lwe_cipher_modulus;
        let ring_dimension = params.ring_dimension;
        let ring_modulus = params.ring_modulus;

        let steps = params.steps;
        let secret_key_type = params.lwe_secret_key_type;
        let ring_secret_key_type = params.ring_secret_key_type;

        // N = 2^i
        if !ring_dimension.is_power_of_two() {
            return Err(FHECoreError::RingDimensionUnValid(ring_dimension));
        }

        let twice_ring_dimension = ring_dimension << 1;
        assert!(twice_ring_dimension != 0, "Ring dimension is too large!");

        // 2N|(Q-1)
        let coeff_modulus: usize = ring_modulus
            .try_into()
            .map_err(|_| "out of range integral type conversion attempted")
            .unwrap();
        let factor = (coeff_modulus - 1) / (twice_ring_dimension);
        if factor * (twice_ring_dimension) != (coeff_modulus - 1) {
            return Err(FHECoreError::RingModulusAndDimensionNotCompatible {
                coeff_modulus: Box::new(coeff_modulus),
                ring_dimension: Box::new(ring_dimension),
            });
        }

        let t = params.lwe_plain_modulus;
        assert!(t.is_power_of_two());
        assert!(lwe_cipher_modulus.is_native() || lwe_cipher_modulus.is_power_of2());
        if let Some(&q) = lwe_cipher_modulus.as_power_of2() {
            assert!(t <= q);
        }

        let lwe_params = LweParameters::new(
            lwe_dimension,
            t,
            lwe_cipher_modulus,
            secret_key_type,
            params.lwe_noise_standard_deviation,
        );

        let blind_rotation_params = BlindRotationParameters::<Q> {
            dimension: ring_dimension,
            modulus: ring_modulus,
            noise_standard_deviation: params.ring_noise_standard_deviation,
            basis: NonPowOf2ApproxSignedBasis::new(
                <Q as Field>::MODULUS_VALUE,
                params.blind_rotation_basis_bits,
                None,
            ),
            secret_key_type: ring_secret_key_type,
        };

        let log_modulus = match steps {
            Steps::BrMsKs => lwe_cipher_modulus.log_modulus(),
            Steps::BrKsRlevMs | Steps::BrKsLevMs => {
                <Q as Field>::ValueT::BITS - <Q as Field>::MODULUS_VALUE.leading_zeros()
            }
            Steps::BrMs => 0,
        };

        let key_switching_params = KeySwitchingParameters {
            input_cipher_dimension: ring_dimension,
            output_cipher_dimension: lwe_dimension,
            log_modulus,
            log_basis: params.key_switching_basis_bits,
            noise_standard_deviation: params.key_switching_standard_deviation,
            reverse_length: None,
        };

        Ok(Self {
            lwe_params,
            blind_rotation_params,
            key_switching_params,
            steps,
        })
    }

    /// Returns the LWE dimension of this [`BooleanFheParameters<C, Q>`], refers to **n** in the paper.
    #[inline]
    pub fn lwe_dimension(&self) -> usize {
        self.lwe_params.dimension
    }

    /// Returns the LWE message modulus of this [`BooleanFheParameters<C, Q>`], refers to **t** in the paper.
    #[inline]
    pub fn lwe_plain_modulus(&self) -> C {
        self.lwe_params.plain_modulus_value
    }

    /// Returns the LWE cipher modulus value of this [`BooleanFheParameters<C, Q>`], refers to **q** in the paper.
    #[inline]
    pub fn lwe_cipher_modulus_value(&self) -> ModulusValue<C> {
        self.lwe_params.cipher_modulus_value
    }

    /// Returns the LWE cipher modulus minus one of this [`BooleanFheParameters<C, Q>`], refers to **q-1** in the paper.
    #[inline]
    pub fn lwe_cipher_modulus_minus_one(&self) -> C {
        self.lwe_params.cipher_modulus_minus_one
    }

    /// Returns the LWE noise error's standard deviation of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn lwe_noise_standard_deviation(&self) -> f64 {
        self.lwe_params.noise_standard_deviation
    }

    /// Returns the LWE Secret Key distribution Type of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn lwe_secret_key_type(&self) -> LweSecretKeyType {
        self.lwe_params.secret_key_type
    }

    /// Returns the ring dimension of this [`BooleanFheParameters<C, Q>`], refers to **N** in the paper.
    #[inline]
    pub fn ring_dimension(&self) -> usize {
        self.blind_rotation_params.dimension
    }

    /// Returns the ring modulus of this [`BooleanFheParameters<C, Q>`], refers to **Q** in the paper.
    #[inline]
    pub fn ring_modulus(&self) -> <Q as Field>::ValueT {
        self.blind_rotation_params.modulus
    }

    /// Returns the ring noise error's standard deviation of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn ring_noise_standard_deviation(&self) -> f64 {
        self.blind_rotation_params.noise_standard_deviation
    }

    /// Returns the ring secret key type of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn ring_secret_key_type(&self) -> RingSecretKeyType {
        self.blind_rotation_params.secret_key_type
    }

    /// Returns the gadget basis of this [`BooleanFheParameters<C, Q>`],
    /// which acts as the decompose basis for `Q` used for bootstrapping accumulator.
    #[inline]
    pub fn blind_rotation_basis(&self) -> &NonPowOf2ApproxSignedBasis<<Q as Field>::ValueT> {
        &self.blind_rotation_params.basis
    }

    /// Returns the key switching basis' bits of this [`BooleanFheParameters<C, Q>`],
    /// which acts as the decompose basis for `Q` or `q` used for key switching.
    #[inline]
    pub fn key_switching_basis_bits(&self) -> u32 {
        self.key_switching_params.log_basis
    }

    /// Returns the key switching error's standard deviation of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn key_switching_noise_standard_deviation(&self) -> f64 {
        self.key_switching_params.noise_standard_deviation
    }

    /// Gets the lwe noise distribution.
    #[inline]
    pub fn lwe_noise_distribution(&self) -> DiscreteGaussian<C> {
        DiscreteGaussian::new(
            0.0,
            self.lwe_noise_standard_deviation(),
            self.lwe_cipher_modulus_minus_one(),
        )
        .unwrap()
    }

    /// Gets the ring noise distribution.
    #[inline]
    pub fn ring_noise_distribution(&self) -> DiscreteGaussian<<Q as Field>::ValueT> {
        DiscreteGaussian::new(0.0, self.ring_noise_standard_deviation(), Q::MINUS_ONE).unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution_for_ring(
        &self,
    ) -> DiscreteGaussian<<Q as Field>::ValueT> {
        DiscreteGaussian::new(
            0.0,
            self.key_switching_noise_standard_deviation(),
            Q::MINUS_ONE,
        )
        .unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution_for_lwe(&self) -> DiscreteGaussian<C> {
        DiscreteGaussian::new(
            0.0,
            self.key_switching_noise_standard_deviation(),
            self.lwe_cipher_modulus_minus_one(),
        )
        .unwrap()
    }

    /// Returns the steps of whole bootstrapping of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn steps(&self) -> Steps {
        self.steps
    }

    /// Returns a reference to the lwe params of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn lwe_params(&self) -> &LweParameters<C> {
        &self.lwe_params
    }

    /// Generates the NTT table.
    #[inline]
    pub fn generate_ntt_table_for_rlwe(&self) -> <Q as NttField>::Table {
        Q::generate_ntt_table(self.ring_dimension().trailing_zeros()).unwrap()
    }

    /// Returns the key switching params of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn key_switching_params(&self) -> KeySwitchingParameters {
        self.key_switching_params
    }
}
