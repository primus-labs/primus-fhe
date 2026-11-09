use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
#[allow(unused_imports)]
use primus_poly::{Polynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::RingContext;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`Polynomial`] with same poly length, `k` is the dimension.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
#[derive(Clone)]
pub struct Glwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Glwe);

impl_iters!(Glwe);
impl_iter_sub_structure!(Glwe, Polynomial, poly);

impl_basic_operation_single_modulus!(Glwe);
impl_neg_single_modulus!(Glwe);
impl_mul_scalar_single_modulus!(Glwe);
impl_mul_factor_single_modulus!(Glwe);
impl_monomial_single_modulus!(Glwe);
impl_plaintext_single_modulus!(Glwe, Polynomial);

impl<S, T> Glwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `poly_length` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_mut_slices(&mut self, poly_length: usize) -> (&mut [T], &mut [T]) {
        let glwe_len = self.as_ref().len();
        self.as_mut().split_at_mut(glwe_len - poly_length)
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
        poly_length: usize,
    ) -> (PolynomialIterMut<'_, T>, Polynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(poly_length);
        (PolynomialIterMut::new(mask, poly_length), Polynomial(body))
    }
}

impl<S, T> Glwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `poly_length` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_slices(&self, poly_length: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        self.as_ref().split_at(glwe_len - poly_length)
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
    pub fn a_b(&self, poly_length: usize) -> (PolynomialIter<'_, T>, Polynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(poly_length);
        (PolynomialIter::new(mask, poly_length), Polynomial(body))
    }

    /// Computes `output = self * (X^exponent - 1)` component-wise in
    /// `Z_q[X]/(X^N + 1)`.
    ///
    /// # Correctness
    ///
    /// `exponent` must belong to `[0, 2N)`. Rotation and subtraction are
    /// fused into one coefficient pass. `poly_length = N` must be a supported
    /// power of two, and both ciphertexts must have equal lengths containing
    /// whole polynomials of length `N`.
    /// Values must be canonical under `modulus`; output is overwritten with
    /// canonical residues in the same coefficient layout.
    ///
    /// # Panics
    ///
    /// Panics if `poly_length` is zero.
    pub fn mul_monomial_sub_one_to<M, B>(
        &self,
        exponent: usize,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert_eq!(self.as_ref().len(), output.as_ref().len());

        for (input, output) in self
            .as_ref()
            .chunks_exact(poly_length)
            .zip(output.as_mut().chunks_exact_mut(poly_length))
        {
            Polynomial(input).mul_monomial_sub_one_to(exponent, &mut Polynomial(output), modulus);
        }
    }
}
