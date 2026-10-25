//! Borrowed external secret roles, retaining owner metadata until client binding.

use primus_glwe::GlweSecretKey;
use primus_integer::FheUint;
use primus_lwe::{LweSecretKey, LweSecretKeyRef};
use primus_reduce::RingContext;

use crate::{PbsOrder, PbsParameters, TfheKeyError};

/// The secret used by external LWE messages in one GLWE PBS order.
///
/// Borrows one owner without copying coefficients or requiring the other setup
/// secret. Family client factories validate the role, layout, distribution and
/// encoded LWE owner's recorded modulus before borrowing a raw LWE view.
/// This enum itself is not a validated binding.
#[derive(Clone, Copy)]
pub enum ExternalLweSecretKey<'a, T: FheUint> {
    /// Small encoded LWE secret for bootstrap-then-key-switch.
    SmallLwe(&'a LweSecretKey<T>),
    /// Signed GLWE coefficients, flattened as kN LWE coefficients, for
    /// key-switch-then-bootstrap. No extraction or secret copy is needed.
    ExtractedGlwe(&'a GlweSecretKey<T>),
}

impl<'a, T: FheUint> ExternalLweSecretKey<'a, T> {
    /// Retains owner metadata until the family domain is checked. Signed GLWE
    /// coefficient magnitudes remain the raw LWE view's caller precondition.
    pub(crate) fn bind<M: RingContext<T>, LM: RingContext<T>>(
        self,
        parameters: &PbsParameters<T, M, LM>,
    ) -> Result<LweSecretKeyRef<'a, T>, TfheKeyError> {
        let actual = match self {
            Self::SmallLwe(_) => PbsOrder::BootstrapKeyswitch,
            Self::ExtractedGlwe(_) => PbsOrder::KeyswitchBootstrap,
        };
        if actual != parameters.pbs_order() {
            return Err(TfheKeyError::PbsOrderMismatch {
                expected: parameters.pbs_order(),
                actual,
            });
        }
        match self {
            Self::SmallLwe(key) => {
                parameters.check_small_lwe_secret_key(key)?;
                Ok(key.as_view())
            }
            Self::ExtractedGlwe(key) => {
                parameters.check_accumulator_secret_key(key)?;
                Ok(LweSecretKeyRef::Signed(key.as_slice()))
            }
        }
    }
}
