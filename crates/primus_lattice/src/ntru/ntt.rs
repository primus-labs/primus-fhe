use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial};
use primus_reduce::FieldContext;

use super::Ntru;

/// A cryptographic structure for NTRU.
///
/// ## Structure of the `data`
///
/// |------h------|
///
/// where `h` is [`NttPolynomial`].
#[derive(Clone)]
pub struct NttNtru<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttNtru<S>);
impl_bytes_conversion!(NttNtru<S>);
impl_zero!(NttNtru<S>);
impl_iters!(NttNtru);
impl_basic_operation_single_modulus!(NttNtru<S>);

impl<S, T> NttNtru<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Transforms `self` to coefficient form and stores in `result`.
    #[inline]
    pub fn write_coeff_form<Table, A>(&self, result: &mut Ntru<A>, ntt_table: &Table)
    where
        A: RawData<Elem = T> + DataMut,
        Table: NttTable<ValueT = T>,
    {
        let p = result.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.inverse_transform_slice(p);
    }

    /// Performs a modular multiplication on the `self` [`NttNtru<S>`] with another `polynomial` [`NttPolynomial`],
    /// stores the result into `result`.
    #[inline]
    pub fn mul_ntt_polynomial_to<M, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttNtru<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        NttPolynomial(self.as_ref()).mul_to(ntt_poly, &mut NttPolynomial(result.as_mut()), modulus);
    }
}

impl<S, T> NttNtru<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Transforms `self` to coefficient form.
    #[inline]
    pub fn into_coeff_form<Table>(mut self, ntt_table: &Table) -> Ntru<S>
    where
        Table: NttTable<ValueT = T>,
    {
        ntt_table.inverse_transform_slice(self.as_mut());
        Ntru::new(self.0)
    }

    /// Multiplies each NTT coefficient by `scalar` modulo `modulus` in place.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: FieldContext<T>,
    {
        ArrayBase(self.as_mut()).mul_scalar_assign(scalar, modulus);
    }

    /// Performs a modular multiplication on the `self` [`NttNtru<S>`] with another `ntt_poly` [`NttPolynomial<A>`].
    #[inline]
    pub fn mul_ntt_polynomial_assign<M, A>(&mut self, ntt_poly: &NttPolynomial<A>, modulus: M)
    where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
    {
        NttPolynomial(self.as_mut()).mul_assign(ntt_poly, modulus);
    }

    /// Performs `self += ntt_ntru * ntt_poly` in place, all in the NTT domain.
    pub fn add_ntt_ntru_mul_ntt_polynomial_assign<M, A, B>(
        &mut self,
        ntt_ntru: &NttNtru<A>,
        ntt_poly: &NttPolynomial<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        NttPolynomial(self.as_mut()).add_mul_assign(
            &NttPolynomial(ntt_ntru.as_ref()),
            ntt_poly,
            modulus,
        );
    }
}
