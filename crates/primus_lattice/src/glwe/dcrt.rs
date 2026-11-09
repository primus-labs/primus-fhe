use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_factor::ShoupFactor;
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut};
use primus_reduce::FieldContext;

use super::CrtGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`DcrtPolynomial`] with same poly length and moduli count, `k` is the dimension.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial contains consecutive modulus blocks in one fixed RNS
/// base order, with the same polynomial length for every modulus.
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
#[derive(Clone)]
pub struct DcrtGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtGlwe);

impl_iters!(DcrtGlwe);
impl_iter_sub_structure!(DcrtGlwe, DcrtPolynomial, dcrt_poly);

impl_basic_operation_multiple_modulus!(DcrtGlwe);
impl_neg_multiple_modulus!(DcrtGlwe);
impl_mul_scalar_multiple_modulus!(DcrtGlwe);
impl_mul_factor_multiple_modulus!(DcrtGlwe);
impl_plaintext_multiple_modulus!(DcrtGlwe, DcrtPolynomial);
impl_dcrt_polynomial_mul!(DcrtGlwe);

impl_crt_ntt!(CrtGlwe, DcrtGlwe);
impl_crt_intt!(DcrtGlwe, CrtGlwe);

impl<S, T> DcrtGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `rns_poly_len` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_mut_slices(&mut self, rns_poly_len: usize) -> (&mut [T], &mut [T]) {
        let glwe_len = self.as_ref().len();
        self.as_mut().split_at_mut(glwe_len - rns_poly_len)
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
        rns_poly_len: usize,
    ) -> (DcrtPolynomialIterMut<'_, T>, DcrtPolynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(rns_poly_len);
        (
            DcrtPolynomialIterMut::new(mask, rns_poly_len),
            DcrtPolynomial(body),
        )
    }

    /// Inverse butterfly with a Shoup-factor DCRT polynomial.
    /// `(self, output) = (self + rhs, (self_orig - rhs) * factor_poly)`.
    ///
    /// `self` and `rhs` are expected in `[0, q)`. Both outputs are written
    /// back in `[0, q)`.
    ///
    /// # Correctness
    ///
    /// Ciphertexts must have equal lengths, compatible keys, and matching
    /// complete DCRT layouts. Each polynomial has `poly_length * moduli.len()`
    /// entries, with nonzero polynomial length and modulus count. The
    /// multiplier contains exactly one such polynomial in the same modulus
    /// and evaluation order. Inputs are canonical residues; both outputs are
    /// canonical. Precomputed factors, when used, must be prepared for the
    /// corresponding modulus. `output` is overwritten.
    ///
    /// # Panics
    ///
    /// Panics when a zero-length polynomial chunk is used.
    pub fn butterfly_mul_factor_to<A, C>(
        &mut self,
        rhs: &DcrtGlwe<A>,
        factor_poly: &[ShoupFactor<T>],
        output: &mut DcrtGlwe<C>,
        poly_length: usize,
        moduli: &[T],
    ) where
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let rns_poly_len = factor_poly.len();
        self.iter_dcrt_poly_mut(rns_poly_len)
            .zip(rhs.iter_dcrt_poly(rns_poly_len))
            .zip(output.iter_dcrt_poly_mut(rns_poly_len))
            .for_each(|((mut a, s), mut b)| {
                a.butterfly_mul_factor_to(&s, factor_poly, &mut b, poly_length, moduli);
            });
    }
}

impl<S, T> DcrtGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    ///
    /// # Correctness
    ///
    /// Storage must contain at least one mask polynomial and one body polynomial,
    /// each with `rns_poly_len` elements. The caller must maintain this layout
    /// and provide a nonzero polynomial length.
    ///
    /// # Panics
    ///
    /// Panics if the supplied polynomial storage length exceeds the ciphertext length.
    #[inline]
    pub fn a_b_slices(&self, rns_poly_len: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        self.as_ref().split_at(glwe_len - rns_poly_len)
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
    pub fn a_b(&self, rns_poly_len: usize) -> (DcrtPolynomialIter<'_, T>, DcrtPolynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(rns_poly_len);
        (
            DcrtPolynomialIter::new(mask, rns_poly_len),
            DcrtPolynomial(body),
        )
    }
}

impl<S, T> CrtGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Performs a multiplication on the `self` [`CrtGlwe<S>`] with another `dcrt_poly` [`DcrtPolynomial<A>`],
    /// store the output into `output` [`DcrtGlwe<T>`].
    ///
    /// # Correctness
    ///
    /// The table, ciphertext, `dcrt_poly`, and `moduli` must use the same
    /// ordered RNS base. Each RNS polynomial has `table.rns_poly_len()`
    /// entries in modulus-major order, and `dcrt_poly` has exactly that length
    /// in the table's evaluation order. Values must be canonical residues.
    /// Output has the same component count and total length as `self` and is
    /// overwritten in DCRT form.
    ///
    /// # Panics
    ///
    /// Panics if input and output storage lengths differ.
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, Table, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        output: &mut DcrtGlwe<B>,
        moduli: &[M],
        table: &DcrtTable<Table>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = table.poly_length().get();
        let rns_poly_len = table.rns_poly_len();

        output.0.copy_from_slice(self.as_ref());

        output.iter_dcrt_poly_mut(rns_poly_len).for_each(|mut x| {
            table.transform_slice(x.0);
            x.mul_assign(dcrt_poly, poly_length, moduli);
        });
    }
}
