use std::ops::{BitAnd, Shr};

use algebra::Bits;
use num_traits::ConstOne;

/// This basis struct is used for decomposition of the primitive type.
#[derive(Debug, Clone, Copy)]
pub struct Basis<T: Copy> {
    basis: T,
    /// The length of the vector of the decomposed `T` based on the basis.
    decompose_len: usize,
    /// A value of the `bits` 1, used for some bit-operation.
    mask: T,
    /// This basis' bits number.
    bits: usize,
}

impl<T> Basis<T>
where
    T: Copy + Bits + ConstOne + std::ops::Shl<usize, Output = T> + std::ops::Sub<Output = T>,
{
    /// Creates a new [`Basis<T>`].
    ///
    /// # Panics
    ///
    /// Panics if .
    pub fn new(bits: u32, modulus: T) -> Self {
        let mut modulus_bits = T::BITS - modulus.leading_zeros();
        if modulus.count_ones() == 1 {
            modulus_bits -= 1;
        }
        if bits > modulus_bits || bits == T::BITS {
            panic!("bits");
        }
        let decompose_len = modulus_bits.div_ceil(bits) as usize;
        let bits = bits as usize;
        let basis = T::ONE << bits;
        let mask = basis - T::ONE;

        Self {
            basis,
            decompose_len,
            mask,
            bits,
        }
    }

    /// Returns the decompose len of this [`Basis<T>`].
    #[inline]
    pub fn decompose_len(&self) -> usize {
        self.decompose_len
    }
}

impl<T: Copy> Basis<T> {
    /// Returns the mask of this [`Basis<T>`].
    ///
    /// mask is a value of the `bits` 1, used for some bit-operation.
    #[inline]
    pub fn mask(&self) -> T {
        self.mask
    }

    /// Returns the basis' bits number of this [`Basis<T>`].
    #[inline]
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Returns the basis of this [`Basis<T>`].
    #[inline]
    pub fn basis(&self) -> T {
        self.basis
    }
}

/// Decompose `self` according to `basis`.
///
/// # Attention
///
/// **`self`** will be modified *after* performing this decomposition.
pub fn decompose_lsb_bits_inplace<T>(data: &mut [T], basis: Basis<T>, destination: &mut [T])
where
    T: Copy + Bits + ConstOne + Shr<usize, Output = T> + BitAnd<Output = T>,
{
    debug_assert_eq!(destination.len(), data.len());
    let mask = basis.mask();
    let bits = basis.bits();

    destination.iter_mut().zip(data).for_each(|(d_i, p_i)| {
        *d_i = *p_i & mask;
        *p_i = *p_i >> bits;
    });
}
