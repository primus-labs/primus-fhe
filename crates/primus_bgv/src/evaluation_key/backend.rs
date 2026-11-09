//! Prepare BGV's numerical Radix or Hybrid key basis.
use std::sync::Arc;

use primus_decompose::DecompositionConfig;
use primus_lattice::{
    hybrid::{HybridModDown, NativeHybridParameters},
    radix::NativeRadixParameters,
};
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

use crate::BgvContext;

use super::{
    BgvEvaluationKeyConfig, BgvEvaluationKeyError,
    error::{validate_level, validate_ordered_moduli, validate_ring_length},
    material::NativeEvaluationKey,
};

impl BgvContext {
    /// Prepares shared signed-radix metadata for role keys at one active Q level.
    /// The owner binds numerical geometry, not secret or NTT provenance.
    /// # Errors
    /// Rejects an unknown level, unsupported decomposition or overflowing shape.
    pub fn radix_key_parameters(
        &self,
        level: usize,
        config: DecompositionConfig,
    ) -> Result<Arc<NativeRadixParameters>, BgvEvaluationKeyError> {
        validate_level(self, level)?;
        Ok(Arc::new(NativeRadixParameters::try_new(
            self.parameters().poly_length(),
            self.base_q(level),
            config,
        )?))
    }

    /// Prepares one native Hybrid key domain using this context's actual prefix.
    ///
    /// The auxiliary primes must be distinct from active Q and coprime to
    /// the plaintext modulus p.
    /// # Errors
    /// Rejects an unprepared level, invalid Hybrid bases or transforms, or an
    /// incompatible partition or plaintext modulus.
    pub fn hybrid_key_parameters(
        &self,
        level: usize,
        decomposition_count: usize,
        auxiliary_moduli: &[u64],
    ) -> Result<Arc<NativeHybridParameters>, BgvEvaluationKeyError> {
        validate_level(self, level)?;
        let parameters = NativeHybridParameters::try_new(
            self.parameters().poly_length(),
            self.base_q(level),
            self.parameters().base_q().moduli_count(),
            auxiliary_moduli,
            decomposition_count,
        )?;
        parameters.validate_mod_down(HybridModDown::PlaintextPreserving(
            self.parameters().plain_modulus().value(),
        ))?;
        Ok(Arc::new(parameters))
    }
}

pub(super) type KeyBase = RNSBase<u64, BarrettModulus<u64>>;

#[derive(Clone)]
pub(super) enum NativeEvaluationBasis {
    Radix(Arc<NativeRadixParameters>),
    Hybrid(Arc<NativeHybridParameters>),
}

impl NativeEvaluationBasis {
    pub(super) fn q_base(&self) -> &KeyBase {
        match self {
            Self::Radix(parameters) => parameters.base_q(),
            Self::Hybrid(parameters) => parameters.hybrid_rns().q_base(),
        }
    }

    pub(super) fn key_base(&self) -> &KeyBase {
        match self {
            Self::Radix(parameters) => parameters.base_q(),
            Self::Hybrid(parameters) => parameters.hybrid_rns().qp_base(),
        }
    }

    pub(super) fn transform_to_ntt(&self, context: &BgvContext, values: &mut [u64]) {
        match self {
            Self::Radix(_) => context.table().transform_prefix_slice(values),
            Self::Hybrid(parameters) => parameters.transform_qp_assign(context.table(), values),
        }
    }
}

impl NativeEvaluationKey {
    pub(super) fn prepare_metadata(
        context: &BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
    ) -> Result<Self, BgvEvaluationKeyError> {
        validate_level(context, level)?;
        let base = context.base_q(level);
        let poly_length = context.parameters().poly_length();
        let n = poly_length.get();
        let p = context.parameters().plain_modulus().value();
        let basis = match config.into() {
            BgvEvaluationKeyConfig::Radix(config) => NativeEvaluationBasis::Radix(Arc::new(
                NativeRadixParameters::try_new(poly_length, base, config)?,
            )),
            BgvEvaluationKeyConfig::PreparedRadix(parameters) => {
                validate_ring_length(parameters.poly_length().get(), n)?;
                validate_ordered_moduli(parameters.base_q().moduli_values(), base.moduli_values())?;
                NativeEvaluationBasis::Radix(parameters)
            }
            BgvEvaluationKeyConfig::Hybrid(parameters) => {
                validate_ring_length(parameters.poly_length().get(), n)?;
                validate_ordered_moduli(
                    parameters.hybrid_rns().q_base().moduli_values(),
                    base.moduli_values(),
                )?;
                // Reject incompatible p/P before a role can consume any randomness.
                parameters.validate_mod_down(HybridModDown::PlaintextPreserving(p))?;
                let error_bound = context
                    .parameters()
                    .encryption_parameters()
                    .noise_distribution()
                    .maximum_magnitude();
                for &modulus in parameters.hybrid_rns().qp_base().moduli_values() {
                    if error_bound >= modulus {
                        return Err(BgvEvaluationKeyError::NoiseSupport {
                            bound: error_bound,
                            modulus,
                        });
                    }
                }
                NativeEvaluationBasis::Hybrid(parameters)
            }
        };
        Ok(Self {
            context: Arc::clone(context.identity()),
            n,
            level,
            p,
            basis,
            columns: Vec::new(),
        })
    }
}
