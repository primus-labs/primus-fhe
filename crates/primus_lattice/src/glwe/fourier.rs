use primus_data::RawData;

use num_complex::Complex64;
use primus_poly::{FourierPolynomialIter, FourierPolynomialIterMut};

/// Fourier-domain GLWE ciphertext.
///
/// ## Layout
///
/// ```text
/// |--a1--| ... |--ak--|--b--|
/// ```
///
/// Each component is a Fourier polynomial of length `fourier_length`.
/// Total data length: `(k + 1) * fourier_length`.
#[derive(Clone)]
pub struct FourierGlwe<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_iters!(FourierGlwe);
impl_fourier_core!(FourierGlwe);
impl_fourier_iter_sub!(
    FourierGlwe,
    FourierPolynomialIter,
    FourierPolynomialIterMut,
    fourier_poly
);

// ---------------------------------------------------------------------------
// GLWE-specific methods
// ---------------------------------------------------------------------------

impl<S> FourierGlwe<S>
where
    S: RawData<Elem = Complex64> + primus_data::Data,
{
    /// Returns the `a` components and `b` component as immutable slices.
    ///
    /// `mid = k * fourier_length` splits the mask from the body.
    /// `mid` must be `<= self.0.len()`.
    #[inline]
    pub fn a_b_slices(&self, mid: usize) -> (&[Complex64], &[Complex64]) {
        self.0.split_at(mid)
    }
}

impl<S> FourierGlwe<S>
where
    S: RawData<Elem = Complex64> + primus_data::DataMut,
{
    /// Returns the `a` components and `b` component as mutable slices.
    #[inline]
    pub fn a_b_mut_slices(&mut self, mid: usize) -> (&mut [Complex64], &mut [Complex64]) {
        self.0.split_at_mut(mid)
    }
}
