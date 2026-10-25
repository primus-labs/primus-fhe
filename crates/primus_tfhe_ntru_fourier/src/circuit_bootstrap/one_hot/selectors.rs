//! Borrowed Fourier selectors, including the nonzero-only branch offset.

use primus_fft::Complex64;
use primus_lattice::ngsw::{FourierNgsw, FourierNgswIter};
use std::ops::Range;

/// A borrowed Fourier NGSW one-hot selector batch.
///
/// Construct with [`crate::circuit_bootstrap::OneHotCircuitBootstrapEvaluator::ngsw_selectors`] or
/// [`crate::circuit_bootstrap::OneHotCircuitBootstrapEvaluator::nonzero_ngsw_selectors`].
/// Storage is `[slot][level][row element]`,
/// without gadget padding; rows contain N/2 complex values.
/// The full batch starts at r=0, the nonzero batch at r=1. Access and iteration
/// use these mathematical branch numbers, rather than compact storage slots.
/// The view checks shape only; output basis, secret and FFT table identity
/// remain those of the evaluator that produced the buffer.
/// It borrows that buffer without allocating, copying or transforming ciphertexts.
#[derive(Clone, Copy)]
pub struct FourierNgswSelectors<'a> {
    data: &'a [Complex64],
    first_selector: usize,
    selector_count: usize,
    selector_len: usize,
}

impl<'a> FourierNgswSelectors<'a> {
    // The evaluator established positive geometry and addressable storage.
    // Callers select only the full range or its nonzero suffix.
    pub(super) fn new(
        data: &'a [Complex64],
        first_selector: usize,
        selector_count: usize,
        selector_len: usize,
    ) -> Self {
        assert_eq!(
            data.len(),
            selector_count * selector_len,
            "one-hot Fourier NGSW selector batch length mismatch"
        );
        Self {
            data,
            first_selector,
            selector_count,
            selector_len,
        }
    }

    /// Returns the mathematical branch numbers represented by this batch.
    #[must_use]
    pub fn selector_range(&self) -> Range<usize> {
        self.first_selector..self.first_selector + self.selector_count
    }

    /// Returns the number of stored selectors, including only represented branches.
    #[must_use]
    pub fn selector_count(&self) -> usize {
        self.selector_count
    }

    /// Returns L*(N/2) complex values per NGSW selector, excluding padding.
    #[must_use]
    pub fn selector_len(&self) -> usize {
        self.selector_len
    }

    /// Borrows delta_r's NGSW, or returns `None` for a branch outside this batch.
    /// In particular, r=0 is absent from a nonzero-only batch.
    #[must_use]
    pub fn selector(&self, r: usize) -> Option<FourierNgsw<&'a [Complex64]>> {
        if !self.selector_range().contains(&r) {
            return None;
        }
        let start = (r - self.first_selector) * self.selector_len;
        Some(FourierNgsw::new(
            &self.data[start..start + self.selector_len],
        ))
    }

    /// Iterates over mathematical branch numbers and borrowed NGSW controls.
    /// Exact batch length was checked at construction, so no tail is discarded.
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (usize, FourierNgsw<&'a [Complex64]>)>
    + DoubleEndedIterator
    + use<'a> {
        self.selector_range()
            .zip(FourierNgswIter::new(self.data, self.selector_len))
    }
}
