use algebra::Bits;
use num_traits::PrimInt;

/// This basis struct is used for decomposition of the primitive type.
#[derive(Debug, Clone, Copy)]
pub struct Basis<T: PrimInt + Bits> {
    basis: T,
    /// The length of the vector of the decomposed [`T`] based on the basis.
    decompose_len: usize,
    /// A value of the `bits` 1, used for some bit-operation.
    mask: T,
    /// This basis' bits number.
    bits: usize,
}

impl<T: PrimInt + Bits> Basis<T> {
    /// Creates a new [`Basis<T>`].
    ///
    /// # Panics
    ///
    /// Panics if .
    pub fn new(bits: u32, modulus: T) -> Self {
        let modulus_bits = T::N_BITS - modulus.leading_zeros();
        if bits > modulus_bits || bits == T::N_BITS {
            panic!("bits");
        }
        let decompose_len = modulus_bits.div_ceil(bits) as usize;
        let bits = bits as usize;
        let basis = T::one() << bits;
        let mask = basis - T::one();

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
pub fn decompose_lsb_bits_inplace<T: PrimInt + Bits>(
    mut data: Vec<T>,
    basis: Basis<T>,
    destination: &mut [T],
) {
    debug_assert_eq!(destination.len(), data.len());
    let mask = basis.mask();
    let bits = basis.bits();

    destination
        .into_iter()
        .zip(&mut data)
        .for_each(|(d_i, p_i)| {
            let temp = *p_i & mask;
            *p_i = *p_i >> bits;
            *d_i = temp;
        });
}
