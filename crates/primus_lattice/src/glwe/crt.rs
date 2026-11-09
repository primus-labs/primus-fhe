use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_poly::{CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut};

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`CrtPolynomial`] with same poly length and moduli count, `k` is the dimension.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial contains consecutive modulus blocks in one fixed RNS
/// base order, with the same polynomial length for every modulus.
#[derive(Clone)]
pub struct CrtGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtGlwe);

impl_iters!(CrtGlwe);
impl_iter_sub_structure!(CrtGlwe, CrtPolynomial, crt_poly);

impl_basic_operation_multiple_modulus!(CrtGlwe);
impl_neg_multiple_modulus!(CrtGlwe);
impl_mul_scalar_multiple_modulus!(CrtGlwe);
impl_mul_factor_multiple_modulus!(CrtGlwe);
impl_monomial_multiple_modulus!(CrtGlwe);
impl_plaintext_multiple_modulus!(CrtGlwe, CrtPolynomial);

impl<S, T> CrtGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `crt_poly_len` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_mut_slices(&mut self, crt_poly_len: usize) -> (&mut [T], &mut [T]) {
        let glwe_len = self.as_ref().len();
        self.as_mut().split_at_mut(glwe_len - crt_poly_len)
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
        crt_poly_len: usize,
    ) -> (CrtPolynomialIterMut<'_, T>, CrtPolynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(crt_poly_len);
        (
            CrtPolynomialIterMut::new(mask, crt_poly_len),
            CrtPolynomial(body),
        )
    }
}

impl<S, T> CrtGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `crt_poly_len` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_slices(&self, crt_poly_len: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        self.as_ref().split_at(glwe_len - crt_poly_len)
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
    pub fn a_b(&self, crt_poly_len: usize) -> (CrtPolynomialIter<'_, T>, CrtPolynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(crt_poly_len);
        (
            CrtPolynomialIter::new(mask, crt_poly_len),
            CrtPolynomial(body),
        )
    }
}
