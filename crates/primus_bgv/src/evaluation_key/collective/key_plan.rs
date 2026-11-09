//! Key-domain metadata and common masks shared by the linear and relin roles.
use crate::BgvContext;

use super::super::{BgvEvaluationKeyConfig, material::NativeEvaluationKey};
use super::messages::{BgvCollectiveError, Binding, validate_distribution};

pub(super) struct KeyPlan<'c> {
    pub(super) binding: Binding<'c>,
    pub(super) template: NativeEvaluationKey,
    pub(super) masks: Vec<u64>,
}

impl<'c> KeyPlan<'c> {
    pub(super) fn new(
        context: &'c BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvCollectiveError> {
        let (binding, template) = Self::prepare(context, level, config)?;
        let mut masks = vec![0; binding.words];
        let uniforms = template.uniform_distributions(context);
        for mask in masks.chunks_exact_mut(template.key_poly_len()) {
            primus_distr::sample_crt_uniform_values_to(mask, template.n, &uniforms, rng);
        }
        Ok(Self {
            binding,
            template,
            masks,
        })
    }

    pub(super) fn from_masks(
        context: &'c BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BgvCollectiveError> {
        let (binding, template) = Self::prepare(context, level, config)?;
        binding.validate(&masks)?;
        Ok(Self {
            binding,
            template,
            masks,
        })
    }

    fn prepare(
        context: &'c BgvContext,
        level: usize,
        config: impl Into<BgvEvaluationKeyConfig>,
    ) -> Result<(Binding<'c>, NativeEvaluationKey), BgvCollectiveError> {
        validate_distribution(context)?;
        let template = NativeEvaluationKey::prepare_metadata(context, level, config)?;
        // One body/common mask per native two-component column.
        let binding = Binding::new(context, template.key_len() / 2, template.key_base());
        Ok((binding, template))
    }
}
