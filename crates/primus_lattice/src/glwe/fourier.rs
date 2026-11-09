use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};

use primus_poly::{FourierPolynomial, FourierPolynomialIter, FourierPolynomialIterMut};

#[allow(unused_imports)]
use super::Glwe;

/// Fourier-domain GLWE ciphertext.
///
/// ## Layout
///
/// ```text
/// |--a1--| ... |--ak--|--b--|
/// ```
///
/// Each component contains `fourier_length` complex values.
/// Total data length: `(k + 1) * fourier_length` complex values.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial occupies `N / 2` complex values in the FFT table's
/// packing order. Ciphertext values use the normalized native-torus scale.
#[derive(Clone)]
pub struct FourierGlwe<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierGlwe);

impl_fourier_iters!(FourierGlwe);
impl_fourier_iter_sub!(
    FourierGlwe,
    FourierPolynomial,
    FourierPolynomialIter,
    FourierPolynomialIterMut,
    fourier_poly
);

impl_fourier_basic_operation!(FourierGlwe);
impl_fourier_polynomial!(FourierGlwe);

impl_fourier_conversion!(Glwe, FourierGlwe);

// ---------------------------------------------------------------------------
// GLWE-specific methods
// ---------------------------------------------------------------------------

impl<S> FourierGlwe<S>
where
    S: Data<Elem = Complex64>,
{
    /// Splits this GLWE into its mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `fourier_length` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_slices(&self, fourier_length: usize) -> (&[Complex64], &[Complex64]) {
        let glwe_len = self.as_ref().len();
        self.as_ref().split_at(glwe_len - fourier_length)
    }

    /// Splits this GLWE into its mask polynomials and body polynomial.
    ///
    /// # Correctness
    ///
    /// Storage and polynomial length must satisfy the layout required by [`Self::a_b_slices`].
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length. Also panics if it is zero.
    #[inline]
    pub fn a_b(
        &self,
        fourier_length: usize,
    ) -> (FourierPolynomialIter<'_>, FourierPolynomial<&[Complex64]>) {
        let (mask, body) = self.a_b_slices(fourier_length);
        (
            FourierPolynomialIter::new(mask, fourier_length),
            FourierPolynomial(body),
        )
    }
}

impl<S> FourierGlwe<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Splits this GLWE into its mutable mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `fourier_length` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_mut_slices(
        &mut self,
        fourier_length: usize,
    ) -> (&mut [Complex64], &mut [Complex64]) {
        let glwe_len = self.as_ref().len();
        self.as_mut().split_at_mut(glwe_len - fourier_length)
    }

    /// Splits this GLWE into its mutable mask polynomials and body polynomial.
    ///
    /// # Correctness
    ///
    /// Storage and polynomial length must satisfy the layout required by [`Self::a_b_slices`].
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length. Also panics if it is zero.
    #[inline]
    pub fn a_b_mut(
        &mut self,
        fourier_length: usize,
    ) -> (
        FourierPolynomialIterMut<'_>,
        FourierPolynomial<&mut [Complex64]>,
    ) {
        let (mask, body) = self.a_b_mut_slices(fourier_length);
        (
            FourierPolynomialIterMut::new(mask, fourier_length),
            FourierPolynomial(body),
        )
    }
}

impl<S> FourierGlwe<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Adds an already encoded plaintext to the body, leaving the mask unchanged.
    ///
    /// # Correctness
    ///
    /// `plaintext` must contain one complete nonempty polynomial in this
    /// ciphertext's representation, modulus domain and plaintext scale.
    /// Storage must contain complete mask polynomials followed by one body.
    /// No encoding, rounding, random sampling or allocation is performed.
    /// The caller maintains the layout.
    /// Fourier inputs must use the same FFT table, evaluation order and
    /// normalized torus scale; this input is an encoded message, not the
    /// unscaled integer multiplier used by Fourier polynomial products.
    ///
    /// # Panics
    ///
    /// Panics if the plaintext storage is longer than the ciphertext storage.
    #[inline]
    pub fn add_plaintext_assign<A>(&mut self, plaintext: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        let body_len = plaintext.as_ref().len();
        let len = self.as_ref().len();
        let body = &mut self.as_mut()[len - body_len..];
        FourierPolynomial(body).add_assign(plaintext);
    }

    /// Subtracts an already encoded plaintext from the body, leaving the mask unchanged.
    ///
    /// # Correctness
    ///
    /// `plaintext` must contain one complete nonempty polynomial in this
    /// ciphertext's representation, modulus domain and plaintext scale.
    /// Storage must contain complete mask polynomials followed by one body.
    /// No encoding, rounding, random sampling or allocation is performed.
    /// The caller maintains the layout.
    /// Fourier inputs must use the same FFT table, evaluation order and
    /// normalized torus scale; this input is an encoded message, not the
    /// unscaled integer multiplier used by Fourier polynomial products.
    ///
    /// # Panics
    ///
    /// Panics if the plaintext storage is longer than the ciphertext storage.
    #[inline]
    pub fn sub_plaintext_assign<A>(&mut self, plaintext: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        let body_len = plaintext.as_ref().len();
        let len = self.as_ref().len();
        let body = &mut self.as_mut()[len - body_len..];
        FourierPolynomial(body).sub_assign(plaintext);
    }

    /// Overwrites this ciphertext with a trivial encryption: zero mask and encoded body.
    ///
    /// # Correctness
    ///
    /// `plaintext` must contain one complete nonempty polynomial in this
    /// ciphertext's representation, modulus domain and plaintext scale.
    /// Storage must contain complete mask polynomials followed by one body.
    /// No encoding, rounding, random sampling or allocation is performed.
    /// The caller maintains the layout.
    /// Fourier inputs must use the same FFT table, evaluation order and
    /// normalized torus scale; this input is an encoded message, not the
    /// unscaled integer multiplier used by Fourier polynomial products.
    ///
    /// # Panics
    ///
    /// Panics if the plaintext storage is longer than the ciphertext storage.
    #[inline]
    pub fn set_trivial<A>(&mut self, plaintext: &FourierPolynomial<A>)
    where
        A: Data<Elem = Complex64>,
    {
        let body_len = plaintext.as_ref().len();
        let len = self.as_ref().len();
        let (mask, body) = self.as_mut().split_at_mut(len - body_len);
        mask.fill(Complex64::default());
        body.copy_from_slice(plaintext.as_ref());
    }
}
