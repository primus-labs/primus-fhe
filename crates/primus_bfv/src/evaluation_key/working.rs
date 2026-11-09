//! Temporarily reduce only a switched component, then restore its key product.
use primus_modulus::BarrettModulus;
use primus_ntt::NttAutomorphismPermutation;
use primus_reduce::ReduceAdd;

use crate::{BfvCiphertext, BfvContext, working_basis::WorkingBasis};

use super::{BfvEvaluationKeyError, material::NativeEvaluationKey, product::NativeGadgetProduct};

pub(super) struct WorkingKeyProduct<'a> {
    key: &'a NativeEvaluationKey,
    product: NativeGadgetProduct<'a>,
    reduced: Option<ReducedProduct<'a>>,
}

struct ReducedProduct<'a> {
    basis: WorkingBasis<'a>,
    component: Vec<u64>,
    product: BfvCiphertext<Vec<u64>>,
}

impl<'a> WorkingKeyProduct<'a> {
    pub(super) fn try_new(
        context: &'a BfvContext,
        external_level: usize,
        key: &'a NativeEvaluationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        key.validate(context)?;
        let reduced = if external_level == key.level {
            // Key binding already established the level and its numerical basis.
            None
        } else {
            let basis = WorkingBasis::try_new(context, external_level, key.level)?;
            Some(ReducedProduct {
                component: vec![0; basis.working_poly_len()],
                product: context.new_ciphertext(key.level),
                basis,
            })
        };
        let product = NativeGadgetProduct::try_from_validated_key(context, key)?;
        Ok(Self {
            key,
            product,
            reduced,
        })
    }

    pub(super) fn poly_len(&self) -> usize {
        self.reduced.as_ref().map_or_else(
            || self.product.poly_len(),
            |reduced| reduced.basis.external_poly_len(),
        )
    }

    pub(super) fn external_level(&self) -> usize {
        self.reduced
            .as_ref()
            .map_or(self.key.level, |reduced| reduced.basis.external_level())
    }

    pub(super) fn context(&self) -> &'a BfvContext {
        self.product.context
    }

    pub(super) fn moduli(&self) -> &'a [BarrettModulus<u64>] {
        self.context()
            .codec(self.external_level())
            .base_q()
            .moduli()
    }

    pub(super) fn product_to(
        &mut self,
        input: &[u64],
        permutation: Option<&NttAutomorphismPermutation>,
        output: &mut [u64],
    ) {
        if let Some(reduced) = &mut self.reduced {
            reduced
                .basis
                .shrink_polynomial_to(input, &mut reduced.component);
            self.product.product_to(
                self.key,
                &reduced.component,
                permutation,
                reduced.product.as_mut(),
            );
            reduced
                .basis
                .restore_ciphertext_to(reduced.product.as_ref(), output);
        } else {
            self.product
                .product_to(self.key, input, permutation, output);
        }
    }

    // A permutation needs only one NTT limb at a time. Reuse the already owned
    // product scratch also when its working basis has fewer limbs than output Q.
    pub(super) fn add_permuted_to(
        &mut self,
        input: &[u64],
        permutation: &NttAutomorphismPermutation,
        output: &mut [u64],
    ) {
        let n = self.product.context.parameters().poly_length().get();
        let moduli = self.moduli();
        let scratch = &mut self.product.coefficient[..n];
        for ((input, output), &q) in input
            .chunks_exact(n)
            .zip(output.chunks_exact_mut(n))
            .zip(moduli)
        {
            permutation.apply_to(input, scratch);
            for (out, &add) in output.iter_mut().zip(scratch.iter()) {
                *out = q.reduce_add(*out, add);
            }
        }
    }
}
