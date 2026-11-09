use crate::{
    BfvContext,
    evaluation_key::{BfvEvaluationKeyConfig, material::NativeEvaluationKey},
};

use super::{
    BfvCollectiveAggregate, BfvCollectiveContribution, BfvCollectiveError,
    contribution::{Binding, validate_payload},
    share::distribution,
};

pub(super) struct EvaluationSetup<'a> {
    pub(super) context: &'a BfvContext,
    pub(super) native: NativeEvaluationKey,
    pub(super) masks: Vec<u64>,
    pub(super) binding: Binding,
}
impl<'a> EvaluationSetup<'a> {
    pub(super) fn new<R: rand::Rng + rand::CryptoRng>(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        let native = NativeEvaluationKey::prepare_metadata(context, level, config)?;
        let mut masks = vec![0; native.key_len() / 2];
        let uniforms: Vec<_> = native
            .key_moduli_values()
            .iter()
            .map(|&q| rand::distr::Uniform::new(0, q).expect("validated modulus"))
            .collect();
        for poly in masks.chunks_exact_mut(native.key_poly_len()) {
            primus_distr::sample_crt_uniform_values_to(poly, native.n, &uniforms, rng);
        }
        Ok(Self {
            context,
            native,
            masks,
            binding: Binding::new(),
        })
    }
    pub(super) fn from_mask(
        context: &'a BfvContext,
        level: usize,
        config: impl Into<BfvEvaluationKeyConfig>,
        masks: Vec<u64>,
    ) -> Result<Self, BfvCollectiveError> {
        distribution(context)?;
        let native = NativeEvaluationKey::prepare_metadata(context, level, config)?;
        validate_payload(
            native.n,
            native.key_moduli_values(),
            &masks,
            native.key_len() / 2,
        )?;
        Ok(Self {
            context,
            native,
            masks,
            binding: Binding::new(),
        })
    }
    pub(super) fn import(
        &self,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'_>, BfvCollectiveError> {
        self.import_len(&self.binding, self.masks.len(), values)
    }
    pub(super) fn import_len<'p>(
        &self,
        binding: &'p Binding,
        len: usize,
        values: Vec<u64>,
    ) -> Result<BfvCollectiveContribution<'p>, BfvCollectiveError> {
        validate_payload(self.native.n, self.native.key_moduli_values(), &values, len)?;
        Ok(BfvCollectiveContribution {
            binding,
            residues: values,
        })
    }
    pub(super) fn aggregate(
        &self,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'_>, BfvCollectiveError> {
        self.aggregate_len(&self.binding, self.masks.len(), expected)
    }
    pub(super) fn aggregate_len<'p>(
        &'p self,
        binding: &'p Binding,
        len: usize,
        expected: usize,
    ) -> Result<BfvCollectiveAggregate<'p>, BfvCollectiveError> {
        BfvCollectiveAggregate::new(
            binding,
            self.native.n,
            self.native.key_moduli(),
            len,
            expected,
        )
    }
    pub(super) fn finalize_linear(
        &self,
        aggregate: BfvCollectiveAggregate<'_>,
    ) -> Result<NativeEvaluationKey, BfvCollectiveError> {
        let bodies = aggregate.finish(&self.binding)?;
        Ok(self.assemble_key(&bodies, self.masks.chunks_exact(self.native.key_poly_len())))
    }

    pub(super) fn assemble_key<'b>(
        &self,
        bodies: &[u64],
        masks: impl Iterator<Item = &'b [u64]>,
    ) -> NativeEvaluationKey {
        let mut key = self.native.empty();
        let len = self.native.key_poly_len();
        for ((out, body), mask) in key
            .columns
            .chunks_exact_mut(2 * len)
            .zip(bodies.chunks_exact(len))
            .zip(masks)
        {
            out[..len].copy_from_slice(body);
            out[len..].copy_from_slice(mask);
        }
        key
    }
}
