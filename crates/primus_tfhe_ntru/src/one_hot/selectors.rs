//! Borrowed coefficient-domain selectors with their mathematical branch numbers.

use std::ops::Range;

use primus_integer::FheUint;
use primus_lattice::nlev::{Nlev, NlevIter};

/// A complete borrowed batch of coefficient-domain NLEV one-hot selectors.
///
/// Construct with [`crate::OneHotLookupTable::nlev_selectors`]. Storage is
/// `[r][level][coefficient]`, for `r=0..M`, without gadget padding. Every row has
/// N coefficients and levels follow the output basis's scalar order. The view
/// records selector boundaries; it does not verify phases, noise or secret identity.
/// It borrows the original buffer without allocating or copying ciphertexts.
#[derive(Clone, Copy)]
pub struct NlevSelectors<'a, T: FheUint> {
    data: &'a [T],
    selector_count: usize,
    selector_len: usize,
}

impl<'a, T: FheUint> NlevSelectors<'a, T> {
    // The lookup table established positive geometry and addressable batch length.
    pub(super) fn new(data: &'a [T], selector_count: usize, selector_len: usize) -> Self {
        assert_eq!(
            data.len(),
            selector_count * selector_len,
            "one-hot NLEV selector batch length mismatch"
        );
        Self {
            data,
            selector_count,
            selector_len,
        }
    }

    /// Returns the mathematical branch numbers represented by this complete batch.
    #[must_use]
    pub fn selector_range(&self) -> Range<usize> {
        0..self.selector_count
    }

    /// Returns the number of selectors in this batch.
    #[must_use]
    pub fn selector_count(&self) -> usize {
        self.selector_count
    }

    /// Returns L*N coefficients per NLEV selector, excluding gadget padding.
    #[must_use]
    pub fn selector_len(&self) -> usize {
        self.selector_len
    }

    /// Borrows delta_r's NLEV, or returns `None` for a branch outside this batch.
    #[must_use]
    pub fn selector(&self, r: usize) -> Option<Nlev<&'a [T]>> {
        if r >= self.selector_count {
            return None;
        }
        let start = r * self.selector_len;
        Some(Nlev::new(&self.data[start..start + self.selector_len]))
    }

    /// Iterates over mathematical branch numbers and borrowed NLEV controls.
    /// Exact batch length was checked at construction, so no tail is discarded.
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (usize, Nlev<&'a [T]>)> + DoubleEndedIterator + use<'a, T>
    {
        NlevIter::new(self.data, self.selector_len).enumerate()
    }
}
