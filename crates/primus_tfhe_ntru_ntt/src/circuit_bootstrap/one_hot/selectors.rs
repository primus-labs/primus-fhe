//! Borrowed NTT selectors, including the nonzero-only branch offset.

use primus_integer::FheUint;
use primus_lattice::ngsw::{NttNgsw, NttNgswIter};
use std::ops::Range;

/// A borrowed NTT NGSW one-hot selector batch.
///
/// Construct with [`crate::circuit_bootstrap::OneHotCircuitBootstrapEvaluator::ngsw_selectors`] or
/// [`crate::circuit_bootstrap::OneHotCircuitBootstrapEvaluator::nonzero_ngsw_selectors`].
/// Storage is `[slot][level][row element]`,
/// without gadget padding; rows contain N NTT ring elements.
/// The full batch starts at r=0, the nonzero batch at r=1. Access and iteration
/// use these mathematical branch numbers, rather than compact storage slots.
/// The view checks shape only; output basis, secret and NTT convention
/// remain those of the evaluator that produced the buffer.
/// It borrows that buffer without allocating, copying or transforming ciphertexts.
#[derive(Clone, Copy)]
pub struct NttNgswSelectors<'a, T: FheUint> {
    data: &'a [T],
    first_selector: usize,
    selector_count: usize,
    selector_len: usize,
}

impl<'a, T: FheUint> NttNgswSelectors<'a, T> {
    // The evaluator established positive geometry and addressable storage.
    // Callers select only the full range or its nonzero suffix.
    pub(super) fn new(
        data: &'a [T],
        first_selector: usize,
        selector_count: usize,
        selector_len: usize,
    ) -> Self {
        assert_eq!(
            data.len(),
            selector_count * selector_len,
            "one-hot NTT NGSW selector batch length mismatch"
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

    /// Returns L*N NTT ring elements per NGSW selector, excluding padding.
    #[must_use]
    pub fn selector_len(&self) -> usize {
        self.selector_len
    }

    /// Borrows delta_r's NGSW, or returns `None` for a branch outside this batch.
    /// In particular, r=0 is absent from a nonzero-only batch.
    #[must_use]
    pub fn selector(&self, r: usize) -> Option<NttNgsw<&'a [T]>> {
        if !self.selector_range().contains(&r) {
            return None;
        }
        let start = (r - self.first_selector) * self.selector_len;
        Some(NttNgsw::new(&self.data[start..start + self.selector_len]))
    }

    /// Iterates over mathematical branch numbers and borrowed NGSW controls.
    /// Exact batch length was checked at construction, so no tail is discarded.
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (usize, NttNgsw<&'a [T]>)> + DoubleEndedIterator + use<'a, T>
    {
        self.selector_range()
            .zip(NttNgswIter::new(self.data, self.selector_len))
    }
}
