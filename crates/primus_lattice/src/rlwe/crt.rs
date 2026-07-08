use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::DcrtTable;
use primus_poly::{ArrayBase, CrtPolynomialIter, CrtPolynomialIterMut, DcrtPolynomial};
use primus_reduce::FieldContext;

use super::DcrtRlwe;

/// An owned CRT-domain RLWE sample backed by a [`Vec<T>`].
pub type CrtRlweOwned<T> = CrtRlwe<Vec<T>>;

/// A cryptographic structure for Ring Learning with Errors (RLWE).
///
/// ## Structure of the `data`
///
/// |------a------|------b------|
///
/// where `a` and `b` are [`primus_poly::CrtPolynomial`] with same poly length and moduli count.
#[derive(Clone)]
pub struct CrtRlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(CrtRlwe<S>);
impl_bytes_conversion!(CrtRlwe<S>);
impl_zero!(CrtRlwe<S>);
impl_iters!(CrtRlwe);
impl_iter_sub_structure!(CrtRlwe<S>, CrtPolynomial, crt_poly);
impl_basic_operation_multiple_modulus!(CrtRlwe<S>);
impl_crt_ntt!(CrtRlwe<S>, DcrtRlwe);

impl<S, T> CrtRlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Performs a multiplication on the `self` [`CrtRlwe<S>`] with another `dcrt_polynomial` [`DcrtPolynomial<A>`],
    /// store the result into `result` [`DcrtRlwe<B>`].
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, Table, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        result: &mut DcrtRlwe<B>,
        moduli: &[M],
        table: &Table,
    ) where
        M: FieldContext<T>,
        Table: DcrtTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = table.poly_length();
        let crt_poly_len = table.crt_poly_length();

        result.0.copy_from_slice(self.as_ref());

        result
            .iter_dcrt_poly_mut(crt_poly_len)
            .for_each(|mut poly| {
                table.transform_slice(poly.0);
                poly.mul_assign(dcrt_poly, poly_length, moduli);
            });
    }
}
