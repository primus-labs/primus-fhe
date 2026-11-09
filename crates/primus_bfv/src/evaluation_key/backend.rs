//! Numerical preparation shared by BFV's native key roles.
use std::sync::Arc;

use primus_decompose::DecompositionConfig;
use primus_lattice::{hybrid::NativeHybridParameters, radix::NativeRadixParameters};
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

use crate::BfvContext;

use super::{
    BfvEvaluationKeyConfig, BfvEvaluationKeyError,
    error::{validate_level, validate_ordered_moduli, validate_ring_length},
    material::NativeEvaluationKey,
};

impl BfvContext {
    /// Prepares shared signed-radix metadata for role keys at one active Q level.
    /// The owner binds numerical geometry, not secret or NTT provenance.
    /// # Errors
    /// Rejects an unknown level, unsupported decomposition or overflowing shape.
    pub fn radix_key_parameters(
        &self,
        level: usize,
        config: DecompositionConfig,
    ) -> Result<Arc<NativeRadixParameters>, BfvEvaluationKeyError> {
        validate_level(self, level)?;
        Ok(Arc::new(NativeRadixParameters::try_new(
            self.parameters().poly_length(),
            self.codec(level).base_q(),
            config,
        )?))
    }
    /// Prepares shared auxiliary key resources at one actual level.
    /// Computation-only BFV multiplication bases are unrelated to this key P.
    ///
    /// # Errors
    /// Rejects unsupported levels, incompatible partitions or invalid auxiliary NTT bases.
    pub fn hybrid_key_parameters(
        &self,
        level: usize,
        decomposition_count: usize,
        auxiliary_moduli: &[u64],
    ) -> Result<Arc<NativeHybridParameters>, BfvEvaluationKeyError> {
        validate_level(self, level)?;
        Ok(Arc::new(NativeHybridParameters::try_new(
            self.parameters().poly_length(),
            self.codec(level).base_q(),
            self.parameters().base_q().moduli_count(),
            auxiliary_moduli,
            decomposition_count,
        )?))
    }
}

type Base = RNSBase<u64, BarrettModulus<u64>>;

#[derive(Clone)]
pub(super) enum NativeEvaluationBasis {
    Radix(Arc<NativeRadixParameters>),
    Hybrid(Arc<NativeHybridParameters>),
}

impl NativeEvaluationBasis {
    pub(super) fn q_base(&self) -> &Base {
        match self {
            Self::Radix(parameters) => parameters.base_q(),
            Self::Hybrid(parameters) => parameters.hybrid_rns().q_base(),
        }
    }

    pub(super) fn key_base(&self) -> &Base {
        match self {
            Self::Radix(parameters) => parameters.base_q(),
            Self::Hybrid(parameters) => parameters.hybrid_rns().qp_base(),
        }
    }

    pub(super) fn transform_to_ntt(&self, context: &BfvContext, poly: &mut [u64]) {
        match self {
            Self::Radix(_) => context.table().transform_prefix_slice(poly),
            Self::Hybrid(parameters) => parameters.transform_qp_assign(context.table(), poly),
        }
    }
}

impl NativeEvaluationKey {
    pub(super) fn prepare_metadata(
        context: &BfvContext,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
    ) -> Result<Self, BfvEvaluationKeyError> {
        validate_level(context, level)?;
        let codec = context.codec(level);
        let poly_length = context.parameters().poly_length();
        let n = poly_length.get();
        let basis = match config.into() {
            BfvEvaluationKeyConfig::Radix(config) => NativeEvaluationBasis::Radix(Arc::new(
                NativeRadixParameters::try_new(poly_length, codec.base_q(), config)?,
            )),
            BfvEvaluationKeyConfig::PreparedRadix(parameters) => {
                validate_ring_length(parameters.poly_length().get(), n)?;
                validate_ordered_moduli(
                    parameters.base_q().moduli_values(),
                    codec.moduli_values(),
                )?;
                NativeEvaluationBasis::Radix(parameters)
            }
            BfvEvaluationKeyConfig::Hybrid(parameters) => {
                validate_ring_length(parameters.poly_length().get(), n)?;
                validate_ordered_moduli(
                    parameters.hybrid_rns().q_base().moduli_values(),
                    codec.moduli_values(),
                )?;
                let bound = context
                    .parameters()
                    .encryption_parameters()
                    .noise_distribution()
                    .maximum_magnitude();
                for &modulus in parameters.hybrid_rns().qp_base().moduli_values() {
                    if bound >= modulus {
                        return Err(BfvEvaluationKeyError::NoiseSupport { bound, modulus });
                    }
                }
                NativeEvaluationBasis::Hybrid(parameters)
            }
        };
        Ok(Self {
            context: Arc::clone(context.identity()),
            level,
            t: codec.t(),
            n,
            basis,
            columns: Vec::new(),
        })
    }
}
