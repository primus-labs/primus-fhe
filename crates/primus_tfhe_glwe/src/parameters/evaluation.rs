//! Server-side state borrowed independently of the client input reducer.

use primus_glwe::{GgswParameters, GlweKeySwitchingParameters};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_reduce::{ModulusSwitch, RingContext};

use super::PbsOrder;

/// Prepared server-side domains, ring parameters and Q→q conversion.
///
/// Borrowed by evaluators independently of the client input reducer. Owns no
/// client codec or LWE sampler; ring gadget/KS parameters are stored only here.
/// Construct through [`super::PbsParameters::try_from_config`]. Matching this metadata
/// does not establish actual secret or transform identity.
#[derive(Clone)]
pub struct PbsEvaluationParameters<T: FheUint, M: RingContext<T>> {
    pub(super) small_dimension: LweDimension,
    pub(super) small_modulus: Option<T>,
    pub(super) small_secret_distr: crate::SecretKeyDistr,
    pub(super) ring_to_small: Option<ModulusSwitch<T>>,
    pub(super) pbs_order: PbsOrder,
    pub(super) blind_rotation_params: GgswParameters<T, M>,
    pub(super) key_switching_params: GlweKeySwitchingParameters<T, M>,
}

impl<T: FheUint, M: RingContext<T>> PbsEvaluationParameters<T, M> {
    /// Checks an independently prepared KS target before key generation or resource binding.
    /// Noise and decomposition may be independently selected, but geometry, Q and the target
    /// secret distribution must match the padded small-LWE domain.
    pub fn check_key_switching_parameters(
        &self,
        parameters: &GlweKeySwitchingParameters<T, M>,
    ) -> Result<(), crate::KeyGenerationError> {
        let glwe = self.blind_rotation_params();
        let output = parameters.output();
        if parameters.input_dimension() != glwe.dimension()
            || output.poly_length() != glwe.poly_length()
            || output.dimension().get()
                != self
                    .small_dimension
                    .get()
                    .div_ceil(glwe.poly_length().get())
            || output.cipher_modulus().explicit_value() != self.ring_modulus().explicit_value()
            || output.secret_key_distr() != self.small_secret_distr
        {
            return Err(crate::KeyGenerationError::IncompatibleKeySwitchingParameters);
        }
        Ok(())
    }

    /// Borrows the prepared Q→q conversion after ring KS and compact extraction.
    /// `None` means equal moduli: callers should skip the entire conversion pass.
    /// Rounding acts on ciphertext coefficients, not the decrypted phase.
    #[must_use]
    pub fn ring_to_small_modulus_switch(&self) -> Option<&ModulusSwitch<T>> {
        self.ring_to_small.as_ref()
    }

    /// Returns the accumulator ring and BR GGSW decomposition.
    #[must_use]
    #[inline]
    pub fn blind_rotation_params(&self) -> &GgswParameters<T, M> {
        &self.blind_rotation_params
    }

    /// Returns the order that determines the external input role.
    #[must_use]
    #[inline]
    pub fn pbs_order(&self) -> PbsOrder {
        self.pbs_order
    }

    /// Returns the client-visible LWE dimension for the selected input role.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> LweDimension {
        match self.pbs_order {
            PbsOrder::BootstrapKeyswitch => self.small_dimension,
            PbsOrder::KeyswitchBootstrap => {
                LweDimension::from(self.blind_rotation_params().glwe_size())
            }
        }
    }

    /// Returns the accumulator and ring evaluation-key modulus Q.
    #[must_use]
    #[inline]
    pub fn ring_modulus(&self) -> M {
        self.blind_rotation_params().cipher_modulus()
    }

    /// Returns the external ciphertext modulus for the selected order.
    /// BR→KS uses q; KS→BR uses Q. `None` denotes the native torus.
    #[must_use]
    pub fn external_modulus_value(&self) -> Option<T> {
        match self.pbs_order {
            PbsOrder::BootstrapKeyswitch => self.small_modulus,
            PbsOrder::KeyswitchBootstrap => self.ring_modulus().explicit_value(),
        }
    }

    /// Borrows ring KS shared by PBS and downstream CBS LWE returns.
    #[must_use]
    pub fn glwe_key_switching(&self) -> &GlweKeySwitchingParameters<T, M> {
        &self.key_switching_params
    }

    /// Returns q; `None` denotes the native modulus.
    #[must_use]
    pub fn small_modulus_value(&self) -> Option<T> {
        self.small_modulus
    }
}
