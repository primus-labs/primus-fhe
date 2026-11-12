//! Fixed two-input block BR with a scoped projection capability.

use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};

use super::OneHotCircuitBootstrapEvaluator;
use crate::{
    Lwe,
    blind_rotation::RotationState,
    block::{rotate_blocks_pair, rotate_blocks_split_pair},
    bootstrap::{BlindRotationPairWorkspace, BootstrapResources},
};

/// One prepared input from [`OneHotCircuitBootstrapEvaluator::with_pair`].
/// This scoped view only permits projection; it cannot replace the current BR or
/// outlive the callback. Consuming it lets both inputs reuse one selector buffer.
/// It owns no allocation or independent transform/product workspace.
pub struct OneHotProjection<'p, 'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    evaluator: &'p mut OneHotCircuitBootstrapEvaluator<'a, T, Table>,
    resources: &'p mut BootstrapResources<'a, T, Table>,
}

impl<'p, 'a, T, Table> OneHotProjection<'p, 'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Writes full coefficient NLEV and/or nonzero transformed NGSW selectors.
    /// NLEV covers r=0..M-1; NGSW covers r=1..M-1. When both are requested,
    /// projections are shared and r=0 is never scheme-switched. Layout and
    /// mathematical contracts are those of the owning one-hot evaluator.
    /// Returns the shared FFT engine so the callback can transform coefficient
    /// NLEVs before their buffer is reused for the second input.
    ///
    /// # Panics
    /// Rejects missing outputs or incorrect exact lengths before output writes.
    pub fn project_to(
        self,
        nlev: Option<&mut [T]>,
        ngsw: Option<&mut [Complex64]>,
    ) -> &'p mut FftEngine<'a, Table> {
        assert!(
            nlev.is_some() || ngsw.is_some(),
            "one-hot projection requires an output"
        );
        self.evaluator
            .check_output_lengths(1, nlev.as_deref(), ngsw.as_deref());
        self.evaluator.project(1, nlev, ngsw, self.resources);
        &mut self.resources.fft
    }
}

impl<'a, T, Table> OneHotCircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Allocates a second input's aggregate, current and exponents for
    /// [`Self::with_pair`]. Supports ordinary and split block BR;
    /// returns `None` for classic resources. Shared Fourier, split recovery,
    /// projection and external-product scratch is not duplicated.
    ///
    /// # Panics
    /// Panics if resources belong to a different context.
    #[must_use]
    pub fn new_pair_workspace(
        &self,
        resources: &BootstrapResources<'a, T, Table>,
    ) -> Option<BlindRotationPairWorkspace<T>> {
        resources.check_context(self.context);
        match &resources.blind_rotation.rotation {
            RotationState::Block { .. } | RotationState::BlockSplit { .. } => {
                Some(BlindRotationPairWorkspace::new(
                    resources.context.blind_rotation(),
                    resources.context.external_lwe_dimension(),
                ))
            }
            RotationState::Binary { .. }
            | RotationState::Ternary { .. }
            | RotationState::Split { .. } => None,
        }
    }

    /// Blind-rotates two Block inputs together, then consumes their projections
    /// in input order. The callback receives index 0 then 1; each scoped view
    /// can write NLEV and/or nonzero NGSW and consumes no additional selector batch.
    /// Complete projection and any buffer consumption inside the callback before
    /// the next input reuses those buffers. Ordinary single-input methods handle
    /// an unpaired tail. No threads, queues or online allocations are introduced.
    ///
    /// # Correctness
    /// Inherits [`Self::one_hot_to`]'s secrets, encoding, residue and noise contracts.
    /// Each input retains its original block/selector order and arithmetic.
    ///
    /// # Panics
    /// Rejects classic resources, a foreign context, input dimensions or workspace
    /// geometry before BR. Projection length checks occur within each callback;
    /// a later panic may leave an earlier callback's output written. Scratch is
    /// overwritten on the next call, including after a callback unwinds.
    pub fn with_pair(
        &mut self,
        inputs: [Lwe<&[T]>; 2],
        second: &mut BlindRotationPairWorkspace<T>,
        resources: &mut BootstrapResources<'a, T, Table>,
        mut consume: impl FnMut(usize, OneHotProjection<'_, 'a, T, Table>),
    ) {
        self.prepare_pair(inputs, second, resources);
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

    /// Prepares two independent BR results in block/control/input order.
    /// The first remains in resources; the second remains in `second` until swapped.
    fn prepare_pair(
        &mut self,
        inputs: [Lwe<&[T]>; 2],
        second: &mut BlindRotationPairWorkspace<T>,
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
            "blind-rotation pair workspace mismatch"
        );
        // Select the supported layout before quantization or LUT writes. Split
        // block scratch keeps its configured precision; no ordinary fallback is
        // selected for a split binding.
        let first_exponents = match &mut resources.blind_rotation.rotation {
            RotationState::Block { scratch, .. } => &mut scratch.exponents,
            RotationState::BlockSplit { scratch, .. } => &mut scratch.exponents,
            RotationState::Binary { .. }
            | RotationState::Ternary { .. }
            | RotationState::Split { .. } => {
                panic!("one-hot pair requires block blind-rotation resources")
            }
        };
        let modulus = parameters.accumulator_ntru().cipher_modulus();
        let modulus_switch = parameters
            .rotation_modulus_switch()
            .with_step(self.lookup_table.rotation_step());
        for ((input, exponents), current) in inputs
            .into_iter()
            .zip([first_exponents, &mut second.exponents])
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
        let buffers = [
            &mut resources.blind_rotation.current,
            &mut resources.blind_rotation.scratch,
        ];
        match &mut resources.blind_rotation.rotation {
            RotationState::Block { key, scratch } => rotate_blocks_pair(
                key,
                scratch,
                second,
                buffers,
                resources.blind_rotation_key.blind_rotation_basis(),
                &mut resources.fft,
            ),
            RotationState::BlockSplit { key, scratch } => {
                rotate_blocks_split_pair(
                    key,
                    scratch,
                    second,
                    buffers,
                    &mut resources.fft,
                    resources
                        .blind_rotation
                        .split
                        .as_mut()
                        .expect("split BR extension established at construction"),
                );
            }
            RotationState::Binary { .. }
            | RotationState::Ternary { .. }
            | RotationState::Split { .. } => {
                panic!("one-hot pair requires block blind-rotation resources")
            }
        }
    }
}
