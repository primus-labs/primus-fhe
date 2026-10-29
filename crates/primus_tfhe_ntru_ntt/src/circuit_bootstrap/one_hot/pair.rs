//! Fixed two-input sparse BR with a scoped projection capability.

use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;

use super::OneHotCircuitBootstrapEvaluator;
use crate::{Lwe, blind_rotation::RotationState, bootstrap::BootstrapResources};

/// One prepared input from [`OneHotCircuitBootstrapEvaluator::with_sparse_pair`].
/// This scoped view only permits projection; it cannot replace the current BR or
/// outlive the callback. Consuming it lets both inputs reuse one selector buffer.
/// It owns no allocation or independent transform/product workspace.
pub struct OneHotProjection<'p, 'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    evaluator: &'p mut OneHotCircuitBootstrapEvaluator<'a, T, Table>,
    resources: &'p mut BootstrapResources<'a, T, Table>,
}

impl<T, Table> OneHotProjection<'_, '_, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Writes full coefficient NLEV and/or nonzero transformed NGSW selectors.
    /// NLEV covers r=0..M-1; NGSW covers r=1..M-1. When both are requested,
    /// projections are shared and r=0 is never scheme-switched. Layout and
    /// mathematical contracts are those of the owning one-hot evaluator. NGSW-only
    /// uses its bound projection strategy; NLEV/dual uses ordinary trace and SS.
    ///
    /// # Panics
    /// Rejects missing outputs or incorrect exact lengths before output writes.
    pub fn project_to(self, nlev: Option<&mut [T]>, ngsw: Option<&mut [T]>) {
        assert!(
            nlev.is_some() || ngsw.is_some(),
            "one-hot projection requires an output"
        );
        self.evaluator
            .check_output_lengths(1, nlev.as_deref(), ngsw.as_deref());
        self.evaluator.project(1, nlev, ngsw, self.resources);
    }
}

impl<'a, T, Table> OneHotCircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Allocates a second input's aggregate, current and exponents for
    /// [`Self::with_sparse_pair`]. Returns `None` for classic or block resources.
    /// Shared transform, projection and external-product scratch is not duplicated.
    ///
    /// # Panics
    /// Panics if resources belong to a different context.
    #[must_use]
    pub fn new_sparse_pair_workspace(
        &self,
        resources: &BootstrapResources<'a, T, Table>,
    ) -> Option<crate::sparse::SparseBlindRotationPairWorkspace<T>> {
        resources.check_context(self.context);
        resources
            .blind_rotation_key
            .sparse_bootstrapping_key()
            .map(|_| {
                crate::sparse::SparseBlindRotationPairWorkspace::new(
                    resources.context.blind_rotation(),
                    resources.context.external_lwe_dimension(),
                )
            })
    }

    /// Blind-rotates two sparse inputs together, then consumes their projections
    /// in input order. The callback receives index 0 then 1; each scoped view
    /// can write NLEV and/or nonzero NGSW and consumes no additional selector batch.
    /// Complete projection and any buffer consumption inside the callback before
    /// the next input reuses those buffers. Ordinary single-input methods handle
    /// an unpaired tail. No threads, queues or online allocations are introduced.
    ///
    /// # Correctness
    /// Inherits [`Self::one_hot_to`]'s secrets, encoding, residue and noise contracts.
    /// Each input retains its original bucket/selector order and arithmetic.
    ///
    /// # Panics
    /// Rejects non-sparse resources, a foreign context, input dimensions or workspace
    /// geometry before BR. Projection length checks occur within each callback;
    /// a later panic may leave an earlier callback's output written. Scratch is
    /// overwritten on the next call, including after a callback unwinds.
    pub fn with_sparse_pair(
        &mut self,
        inputs: [Lwe<&[T]>; 2],
        second: &mut crate::sparse::SparseBlindRotationPairWorkspace<T>,
        resources: &mut BootstrapResources<'a, T, Table>,
        mut consume: impl FnMut(usize, OneHotProjection<'_, 'a, T, Table>),
    ) {
        self.prepare_sparse_pair(inputs, second, resources);
        consume(
            0,
            OneHotProjection {
                evaluator: self,
                resources,
            },
        );
        core::mem::swap(&mut second.current, &mut resources.blind_rotation.current);
        consume(
            1,
            OneHotProjection {
                evaluator: self,
                resources,
            },
        );
    }

    /// Prepares two independent BR results in bucket/pair/input order.
    /// The first remains in resources; the second remains in `second` until swapped.
    fn prepare_sparse_pair(
        &mut self,
        inputs: [Lwe<&[T]>; 2],
        second: &mut crate::sparse::SparseBlindRotationPairWorkspace<T>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        use primus_poly::Polynomial;
        resources.check_context(self.context);
        let parameters = resources.context;
        let n = parameters.poly_length().get();
        assert!(
            inputs
                .iter()
                .all(|input| input.dimension() == parameters.external_lwe_dimension().get()),
            "one-hot input dimension mismatch"
        );
        assert_eq!(
            (
                second.current.as_ref().len(),
                second.aggregate.len(),
                second.exponents.len()
            ),
            (
                n,
                parameters.blind_rotation().nlev_len(),
                parameters.external_lwe_dimension().get()
            ),
            "sparse pair workspace mismatch"
        );
        let RotationState::Sparse {
            key,
            scratch: workspace,
        } = &mut resources.blind_rotation.rotation
        else {
            panic!("one-hot pair requires sparse blind-rotation resources");
        };
        let modulus = parameters.accumulator_ntru().cipher_modulus();
        let modulus_switch = parameters
            .rotation_modulus_switch()
            .with_step(self.lookup_table.rotation_step());
        for ((input, exponents), current) in inputs
            .into_iter()
            .zip([&mut workspace.exponents, &mut second.exponents])
            .zip([&mut resources.blind_rotation.current, &mut second.current])
        {
            modulus_switch.exponent_slice_to(input.a(), exponents);
            let exponent = modulus_switch.exponent(input.b()).wrapping_neg() & (2 * n - 1);
            self.lookup_table.polynomial().mul_monomial_to(
                exponent,
                &mut Polynomial(current.as_mut()),
                modulus,
            );
        }
        crate::sparse::rotate_buckets_pair(
            key,
            workspace,
            second,
            [
                &mut resources.blind_rotation.current,
                &mut resources.blind_rotation.scratch,
            ],
            resources.blind_rotation_key.blind_rotation_basis(),
            modulus,
            resources.context.table(),
        );
    }
}
