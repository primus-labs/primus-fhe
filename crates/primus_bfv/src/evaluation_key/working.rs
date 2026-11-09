//! Temporarily reduce only a switched component, then restore its key product.
use super::*;
use crate::working_basis::WorkingBasis;

pub(super) struct WorkingKeyProduct<'a> {
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
        let product = NativeGadgetProduct::try_new(context, key)?;
        // Validate even the identity case. No smaller-context/key projection is
        // inferred from an equal storage length or an unrelated key's metadata.
        let basis = WorkingBasis::try_new(context, external_level, key.level)?;
        let reduced = if external_level == key.level {
            None
        } else {
            Some(ReducedProduct {
                component: vec![0; basis.working_poly_len()],
                product: context.new_ciphertext(key.level),
                basis,
            })
        };
        Ok(Self { product, reduced })
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
            .map_or(self.product.key.level, |reduced| {
                reduced.basis.external_level()
            })
    }

    pub(super) fn context(&self) -> &'a BfvContext {
        self.product.context
    }

    pub(super) fn product_to<B: DataMut<Elem = u64>>(
        &mut self,
        input: &[u64],
        permutation: Option<&NttAutomorphismPermutation>,
        output: &mut BfvCiphertext<B>,
    ) {
        if let Some(reduced) = &mut self.reduced {
            reduced
                .basis
                .shrink_polynomial_to(input, &mut reduced.component);
            self.product
                .product_to(&reduced.component, permutation, &mut reduced.product);
            reduced
                .basis
                .restore_polynomials_to(reduced.product.as_ref(), output.as_mut(), 2);
        } else {
            self.product.product_to(input, permutation, output);
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
        let moduli = self
            .product
            .context
            .codec(self.external_level())
            .base_q()
            .moduli();
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
