//! Representation selection stays at trace, not at the BR/SS/client boundary.
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweTraceKey, FourierGlweTraceWorkspace};
#[cfg(feature = "split-trace")]
use primus_glwe::{SplitFourierGlweTraceKey, SplitFourierGlweTraceWorkspace};
use primus_lattice::{GlweSize, glwe::Glwe};

/// The selected reverse-trace material; no unused alternative is retained.
/// Selected by [`crate::CbsConfig::fourier_trace_precision`]. Evaluators allocate
/// matching scratch from this material when composing standalone GLWE operations.
pub enum CbsTraceKey<T: TorusFftValue> {
    /// Original direct Fourier trace material.
    Ordinary(FourierGlweTraceKey<T>),
    /// Split(35) trace material generated from exact coefficient keys.
    #[cfg(feature = "split-trace")]
    Split35(SplitFourierGlweTraceKey<T>),
}
/// Mutable storage is chosen from the actual key when binding an evaluator.
pub(super) enum CbsTraceWorkspace<T: TorusFftValue> {
    Ordinary(FourierGlweTraceWorkspace<T>),
    #[cfg(feature = "split-trace")]
    Split35(SplitFourierGlweTraceWorkspace<T>),
}
impl<T: TorusFftValue> CbsTraceKey<T> {
    pub(super) fn basis(&self) -> &ApproxSignedBasis<T> {
        match self {
            Self::Ordinary(k) => k.basis(),
            #[cfg(feature = "split-trace")]
            Self::Split35(k) => k.basis(),
        }
    }
    pub(super) fn new_workspace(&self, size: GlweSize) -> CbsTraceWorkspace<T> {
        match self {
            Self::Ordinary(_) => CbsTraceWorkspace::Ordinary(FourierGlweTraceWorkspace::new(size)),
            #[cfg(feature = "split-trace")]
            Self::Split35(k) => CbsTraceWorkspace::Split35(k.new_workspace()),
        }
    }
    /// Dispatch once for the complete projection, outside trace and coefficient loops.
    pub(super) fn project_to<Table: FftTable>(
        &self,
        input: Glwe<&[T]>,
        count: usize,
        output: &mut [T],
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut CbsTraceWorkspace<T>,
    ) {
        match (self, workspace) {
            (Self::Ordinary(k), CbsTraceWorkspace::Ordinary(w)) => {
                k.project_prefix_coefficients_to(&input, count, output, fft, w)
            }
            #[cfg(feature = "split-trace")]
            (Self::Split35(k), CbsTraceWorkspace::Split35(w)) => {
                k.project_prefix_coefficients_to(&input, count, output, fft, w)
            }
            #[cfg(feature = "split-trace")]
            _ => panic!("CBS trace workspace representation mismatch"),
        }
    }
}
