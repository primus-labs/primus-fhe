mod cmux;
mod external_product;
mod ternary;

use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};
use primus_poly::FourierPolynomial;

#[allow(unused_imports)]
use super::Ggsw;
#[allow(unused_imports)]
use crate::glev::{FourierGlev, FourierGlevIter, FourierGlevIterMut};

/// Fourier-domain GGSW ciphertext — matrix of
/// [`FourierGlev`], one per row.
///
/// ## Layout
///
/// ```text
/// |--row_0--| ... |--row_k--|
/// ```
///
/// Each row is a [`FourierGlev`] of length
/// `fourier_glev_len`.
/// Total data length: `(k + 1) * fourier_glev_len`.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial occupies `N / 2` complex values in the FFT table's
/// packing order. Ciphertext values use the normalized native-torus scale.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct FourierGgsw<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierGgsw);

impl_fourier_iters!(FourierGgsw);
impl_fourier_iter_sub!(
    FourierGgsw,
    FourierGlev,
    FourierGlevIter,
    FourierGlevIterMut,
    glev
);

impl_fourier_basic_operation!(FourierGgsw);
impl_fourier_polynomial!(FourierGgsw);
impl_fourier_monomial!(FourierGgsw);

impl_fourier_conversion!(Ggsw, FourierGgsw);

impl<S> FourierGgsw<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Adds an already gadget-weighted plaintext to the diagonal of one level.
    ///
    /// Storage is `[row][level][component][polynomial entry]`. The number
    /// of components equals the number of rows. `level` is
    /// a zero-based storage index; the caller maps it to its gadget weight.
    /// Every diagonal polynomial at this level receives `plaintext`, while
    /// other levels and off-diagonal components remain unchanged.
    ///
    /// # Correctness
    ///
    /// `plaintext` must be one complete nonempty polynomial already multiplied
    /// by the selected gadget weight and encoded in this ciphertext's domain
    /// and scale. This performs neither encoding nor encryption, and allocates
    /// no temporary storage. Adding all levels implements addition of `m*G`
    /// under the caller's gadget convention.
    /// `size` must describe the complete ciphertext and plaintext layouts.
    /// `level` must be less than its decomposition length. The caller is
    /// responsible for matching the actual buffers to `size`.
    /// Inputs must share the FFT table, evaluation order and torus scale.
    #[inline]
    pub fn add_gadget_diagonal_assign<A>(
        &mut self,
        plaintext: &FourierPolynomial<A>,
        level: usize,
        size: crate::GadgetSize,
    ) where
        A: Data<Elem = Complex64>,
    {
        let glwe_size = size.glwe_size();
        debug_assert!(
            level < size.level_count().get(),
            "gadget level is out of range"
        );
        for diagonal in crate::gadget::diagonal_level_mut(
            self.as_mut(),
            glwe_size.fourier_poly_len(),
            level,
            glwe_size.fourier_glwe_len(),
            size.fourier_glev_len(),
        ) {
            FourierPolynomial(diagonal).add_assign(plaintext);
        }
    }
}
