//! The basis for decomposition of the [`Field`].

use num_traits::{ConstOne, One};

use crate::{Bits, ConstBounded, DecomposableField, Field};

/// This basis struct is used for decomposition of the [`Field`].
///
/// It is designed for powers of 2 basis.
/// In this case, decomposition will become simple and efficient.
#[derive(Debug, Clone, Copy)]
pub struct Basis<F: DecomposableField> {
    basis: F::Value,
    /// The length of the vector of the decomposed [`Field`] based on the basis.
    decompose_len: usize,
    /// A value of the `bits` 1, used for some bit-operation.
    mask: F::Value,
    /// This basis' bits number.
    bits: u32,
}

impl<F: DecomposableField> Default for Basis<F> {
    #[inline]
    fn default() -> Self {
        Self::new(1)
    }
}

impl<F: DecomposableField> Basis<F> {
    /// Creates a new [`Basis<F>`] with the given basis' bits number.
    pub fn new(bits: u32) -> Self {
        let mut modulus_bits =
            <F::Value as Bits>::BITS - num_traits::PrimInt::leading_zeros(F::MODULUS_VALUE);

        assert!(modulus_bits >= bits);

        if num_traits::PrimInt::count_ones(F::MODULUS_VALUE).is_one() {
            modulus_bits -= 1;
        }

        let mask = <F::Value as ConstBounded>::MAX >> (<F::Value as Bits>::BITS - bits);
        let basis = <F::Value as ConstOne>::ONE << bits;
        let decompose_len = modulus_bits.div_ceil(bits) as usize;

        Self {
            basis,
            decompose_len,
            mask,
            bits,
        }
    }

    /// Returns the decompose len of this [`Basis<F>`].
    #[inline]
    pub fn decompose_len(&self) -> usize {
        self.decompose_len
    }

    /// Returns the mask of this [`Basis<F>`].
    ///
    /// mask is a value of the `bits` 1, used for some bit-operation.
    #[inline]
    pub fn mask(&self) -> <F as Field>::Value {
        self.mask
    }

    /// Returns the basis' bits number of this [`Basis<F>`].
    #[inline]
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Returns the basis of this [`Basis<F>`].
    #[inline]
    pub fn basis(&self) -> <F as Field>::Value {
        self.basis
    }
}
