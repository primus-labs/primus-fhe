use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::FieldContext;

use super::NttGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`primus_poly::Polynomial`] with same poly length, `k` is the dimension.
#[derive(Clone)]
pub struct Glwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Glwe<S>);
impl_bytes_conversion!(Glwe<S>);
impl_zero!(Glwe<S>);
impl_iters!(Glwe);
impl_iter_sub_structure!(Glwe<S>, Polynomial, poly);
impl_basic_operation_single_modulus!(Glwe<S>);
impl_ntt!(Glwe<S>, NttGlwe);

impl<S, T> Glwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs a multiplication on the `self` [`Glwe<S>`] with another `ntt_poly` [`NttPolynomial<A>`],
    /// store the result into `result` [`NttGlwe<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttGlwe<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let ntt_poly_len = ntt_table.poly_length();

        result.0.copy_from_slice(self.as_ref());

        result.iter_ntt_poly_mut(ntt_poly_len).for_each(|mut poly| {
            ntt_table.transform_slice(poly.0);
            poly.mul_assign(ntt_poly, modulus);
        });
    }
}
