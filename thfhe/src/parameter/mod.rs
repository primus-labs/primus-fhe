//! The parameters of the fully homomorphic encryption scheme.

use algebra::decompose::NonPowOf2ApproxSignedBasis;
use algebra::random::DiscreteGaussian;
use algebra::reduce::Modulus;
use algebra::reduce::ModulusValue;
use algebra::Field;
use algebra::NttField;
use fhe_core::{FHECoreError, GadgetRlweParameters as BlindRotationParameters};
use fhe_core::{KeySwitchingParameters, LweParameters, LweSecretKeyType, RingSecretKeyType};

mod constants;

pub use constants::*;

/// The parameters of the fully homomorphic encryption scheme.
///
/// This type is used for setting some default Parameters.
#[derive(Debug, Clone, Copy)]
pub struct ConstParameters {
    /// **LWE** vector dimension, refers to **n** in the paper.
    pub lwe_dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    pub lwe_plain_modulus: u64,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    pub lwe_cipher_modulus: ModulusValue<u64>,
    /// The **LWE** noise error's standard deviation.
    pub lwe_noise_standard_deviation: f64,
    /// **LWE** Secret Key distribution Type.
    pub lwe_secret_key_type: LweSecretKeyType,

    /// **Ring** polynomial dimension, refers to **N** in the paper.
    pub ring_dimension: usize,
    /// **Ring** polynomial modulus, refers to **Q** in the paper.
    pub ring_modulus: u64,
    /// The **Ring** noise error's standard deviation for **rlwe**.
    pub ring_noise_standard_deviation: f64,
    /// The distribution type of the **Ring** Secret Key.
    pub ring_secret_key_type: RingSecretKeyType,

    /// Decompose basis' bits for `Q` used for blind rotation accumulator.
    pub blind_rotation_basis_bits: u32,

    /// Decompose basis' bits for `Q` or `q` used for key switching.
    pub key_switching_basis_bits: u32,
    /// The noise error's standard deviation for key switching **rlwe** or **lwe**.
    pub key_switching_standard_deviation: f64,
}

/// Parameters for the boolean fully homomorphic encryption scheme.
#[derive(Debug)]
pub struct ThFheParameters {
    input_lwe_params: LweParameters<<Fp as Field>::ValueT, <Fp as Field>::Modulus>,
    key_switching_params: KeySwitchingParameters,
    intermediate_lwe_params: LweParameters<<Fp as Field>::ValueT, <Fp as Field>::Modulus>,
    blind_rotation_params: BlindRotationParameters<Fp>,
}

impl Clone for ThFheParameters {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for ThFheParameters {}

impl ThFheParameters {
    /// Create a new Parameter instance.
    pub fn new(params: ConstParameters) -> Result<Self, FHECoreError> {
        let lwe_dimension = params.lwe_dimension;
        let lwe_cipher_modulus = params.lwe_cipher_modulus;
        let ring_dimension = params.ring_dimension;
        let ring_modulus = params.ring_modulus;

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
        let lwe_cipher_modulus = <Fp as Field>::Modulus::from_value(lwe_cipher_modulus);

        let lwe_params = LweParameters::new(
            lwe_dimension,
            t,
            lwe_cipher_modulus,
            secret_key_type,
            params.lwe_noise_standard_deviation,
        );

        let blind_rotation_params = BlindRotationParameters {
            dimension: ring_dimension,
            modulus: ring_modulus,
            noise_standard_deviation: params.ring_noise_standard_deviation,
            basis: NonPowOf2ApproxSignedBasis::new(
                <Fp as Field>::MODULUS_VALUE,
                params.blind_rotation_basis_bits,
                None,
            ),
            secret_key_type: ring_secret_key_type,
        };

        let log_modulus =
            <Fp as Field>::ValueT::BITS - <Fp as Field>::MODULUS_VALUE.leading_zeros();

        let key_switching_params = KeySwitchingParameters {
            input_cipher_dimension: ring_dimension,
            output_cipher_dimension: lwe_dimension,
            log_modulus,
            log_basis: params.key_switching_basis_bits,
            noise_standard_deviation: params.key_switching_standard_deviation,
            reverse_length: None,
        };

        Ok(Self {
            input_lwe_params: LweParameters::new(
                ring_dimension,
                t,
                Fp::MODULUS,
                match ring_secret_key_type {
                    RingSecretKeyType::Binary => LweSecretKeyType::Binary,
                    RingSecretKeyType::Ternary => LweSecretKeyType::Ternary,
                    RingSecretKeyType::Gaussian => {
                        panic!("Gaussian secret key type is not supported")
                    }
                },
                params.ring_noise_standard_deviation,
            ),
            intermediate_lwe_params: lwe_params,
            blind_rotation_params,
            key_switching_params,
        })
    }

    /// Returns the LWE message modulus of this [`BooleanFheParameters<C, Q>`], refers to **t** in the paper.
    #[inline]
    pub fn lwe_plain_modulus(&self) -> <Fp as Field>::ValueT {
        self.input_lwe_params.plain_modulus_value
    }

    /// Returns the LWE dimension of this [`BooleanFheParameters<C, Q>`], refers to **n** in the paper.
    #[inline]
    pub fn input_lwe_dimension(&self) -> usize {
        self.input_lwe_params.dimension
    }

    /// Returns the LWE noise error's standard deviation of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn input_lwe_noise_standard_deviation(&self) -> f64 {
        self.input_lwe_params.noise_standard_deviation
    }

    /// Returns the LWE cipher modulus of this [`BooleanFheParameters<C, Q>`], refers to **q** in the paper.
    #[inline]
    pub fn input_lwe_cipher_modulus(&self) -> <Fp as Field>::Modulus {
        self.input_lwe_params.cipher_modulus
    }

    /// Returns the LWE cipher modulus value of this [`BooleanFheParameters<C, Q>`], refers to **q** in the paper.
    #[inline]
    pub fn input_lwe_cipher_modulus_value(&self) -> ModulusValue<<Fp as Field>::ValueT> {
        self.input_lwe_params.cipher_modulus_value
    }

    /// Returns the LWE cipher modulus minus one of this [`BooleanFheParameters<C, Q>`], refers to **q-1** in the paper.
    #[inline]
    pub fn input_lwe_cipher_modulus_minus_one(&self) -> <Fp as Field>::ValueT {
        self.input_lwe_params.cipher_modulus_minus_one
    }

    /// Returns the LWE Secret Key distribution Type of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn input_lwe_secret_key_type(&self) -> LweSecretKeyType {
        self.input_lwe_params.secret_key_type
    }

    /// Returns the LWE dimension of this [`BooleanFheParameters<C, Q>`], refers to **n** in the paper.
    #[inline]
    pub fn intermediate_lwe_dimension(&self) -> usize {
        self.intermediate_lwe_params.dimension
    }

    /// Returns the LWE cipher modulus of this [`BooleanFheParameters<C, Q>`], refers to **q** in the paper.
    #[inline]
    pub fn intermediate_lwe_cipher_modulus(&self) -> <Fp as Field>::Modulus {
        self.intermediate_lwe_params.cipher_modulus
    }

    /// Returns the LWE cipher modulus value of this [`BooleanFheParameters<C, Q>`], refers to **q** in the paper.
    #[inline]
    pub fn intermediate_lwe_cipher_modulus_value(&self) -> ModulusValue<<Fp as Field>::ValueT> {
        self.intermediate_lwe_params.cipher_modulus_value
    }

    /// Returns the LWE cipher modulus minus one of this [`BooleanFheParameters<C, Q>`], refers to **q-1** in the paper.
    #[inline]
    pub fn intermediate_lwe_cipher_modulus_minus_one(&self) -> <Fp as Field>::ValueT {
        self.intermediate_lwe_params.cipher_modulus_minus_one
    }

    /// Returns the LWE Secret Key distribution Type of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn intermediate_lwe_secret_key_type(&self) -> LweSecretKeyType {
        self.intermediate_lwe_params.secret_key_type
    }

    /// Returns the ring dimension of this [`BooleanFheParameters<C, Q>`], refers to **N** in the paper.
    #[inline]
    pub fn ring_dimension(&self) -> usize {
        self.blind_rotation_params.dimension
    }

    /// Returns the ring modulus of this [`BooleanFheParameters<C, Q>`], refers to **Q** in the paper.
    #[inline]
    pub fn ring_modulus(&self) -> <Fp as Field>::ValueT {
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
    pub fn blind_rotation_basis(&self) -> &NonPowOf2ApproxSignedBasis<<Fp as Field>::ValueT> {
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
    pub fn input_lwe_noise_distribution(&self) -> DiscreteGaussian<<Fp as Field>::ValueT> {
        DiscreteGaussian::new(
            0.0,
            self.input_lwe_noise_standard_deviation(),
            self.input_lwe_cipher_modulus_minus_one(),
        )
        .unwrap()
    }

    /// Gets the ring noise distribution.
    #[inline]
    pub fn ring_noise_distribution(&self) -> DiscreteGaussian<<Fp as Field>::ValueT> {
        DiscreteGaussian::new(0.0, self.ring_noise_standard_deviation(), Fp::MINUS_ONE).unwrap()
    }

    /// Gets the key_switching noise distribution.
    #[inline]
    pub fn key_switching_noise_distribution(&self) -> DiscreteGaussian<<Fp as Field>::ValueT> {
        DiscreteGaussian::new(
            0.0,
            self.key_switching_noise_standard_deviation(),
            Fp::MINUS_ONE,
        )
        .unwrap()
    }

    /// Returns a reference to the lwe params of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn input_lwe_params(
        &self,
    ) -> &LweParameters<<Fp as Field>::ValueT, <Fp as Field>::Modulus> {
        &self.input_lwe_params
    }

    /// Returns a reference to the lwe params of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn intermediate_lwe_params(
        &self,
    ) -> &LweParameters<<Fp as Field>::ValueT, <Fp as Field>::Modulus> {
        &self.intermediate_lwe_params
    }

    /// Generates the NTT table.
    #[inline]
    pub fn generate_ntt_table_for_rlwe(&self) -> <Fp as NttField>::Table {
        Fp::generate_ntt_table(self.ring_dimension().trailing_zeros()).unwrap()
    }

    /// Returns the key switching params of this [`BooleanFheParameters<C, Q>`].
    #[inline]
    pub fn key_switching_params(&self) -> KeySwitchingParameters {
        self.key_switching_params
    }
}
