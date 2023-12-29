//! basis for decompose

use crate::ring::Ring;

/// power of two basis
#[derive(Debug, Clone, Copy)]
pub struct Basis<R: Ring> {
    basis: R::Inner,
    decompose_len: usize,
    mask: R::Inner,
    bits: u32,
}

impl<R: Ring> Basis<R> {
    /// Creates a new [`Basis<R>`].
    pub fn new(bits: u32) -> Self {
        let basis = R::pow_of_two(bits);
        let mask = R::mask(bits);
        let basis = basis.inner();
        let decompose_len = R::decompose_len(basis);

        Self {
            basis,
            decompose_len,
            mask,
            bits,
        }
    }

    /// Returns the decompose len of this [`Basis<R>`].
    #[inline]
    pub fn decompose_len(&self) -> usize {
        self.decompose_len
    }

    /// Returns the mask of this [`Basis<R>`].
    #[inline]
    pub fn mask(&self) -> <R as Ring>::Inner {
        self.mask
    }

    /// Returns the bits of this [`Basis<R>`].
    #[inline]
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Returns the basis of this [`Basis<R>`].
    #[inline]
    pub fn basis(&self) -> <R as Ring>::Inner {
        self.basis
    }
}
