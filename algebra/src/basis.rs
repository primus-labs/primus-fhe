//! basis for decomposition of the [`Ring`].

use crate::Ring;

/// This basis struct is used for decomposition of the [`Ring`].
///
/// It is designed for powers of 2 basis. In this case, decomposition will become simple and efficient.
#[derive(Debug, Clone, Copy)]
pub struct Basis<R: Ring> {
    basis: R::Inner,
    /// The length of the vector of the decomposed [`Ring`] based on the basis.
    decompose_len: usize,
    /// A value of the `bits` 1, used for some bit-operation.
    mask: R::Inner,
    /// This basis' bits number.
    bits: u32,
}

impl<R: Ring> Basis<R> {
    /// Creates a new [`Basis<R>`] with the given basis' bits number.
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
    ///
    /// mask is a value of the `bits` 1, used for some bit-operation.
    #[inline]
    pub fn mask(&self) -> <R as Ring>::Inner {
        self.mask
    }

    /// Returns the basis' bits number of this [`Basis<R>`].
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
