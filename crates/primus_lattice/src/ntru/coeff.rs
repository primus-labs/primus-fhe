use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use super::NttNtru;

/// A cryptographic structure for NTRU.
///
/// ## Structure of the `data`
///
/// |------h------|
///
/// where `h` is [`Polynomial`].
#[derive(Clone)]
pub struct Ntru<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Ntru<S>);
impl_bytes_conversion!(Ntru<S>);
impl_zero!(Ntru<S>);
impl_iters!(Ntru);
impl_basic_operation_single_modulus!(Ntru<S>);

impl<S, T> Ntru<S>
where
    S: RawData<Elem = T> + DataOwned,
    T: FheUint,
{
    /// Creates a new [`Ntru<S>`] with reference of [`Polynomial<A>`].
    #[inline]
    pub fn from_ref<A>(h: &Polynomial<A>) -> Self
    where
        A: RawData<Elem = T> + Data,
    {
        Self(S::from_vec(h.as_ref().to_vec()))
    }
}

impl<S, T> Ntru<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Transforms `self` to ntt form and stores in `result`.
    #[inline]
    pub fn write_ntt_form<Table, A>(&self, result: &mut NttNtru<A>, ntt_table: &Table)
    where
        A: RawData<Elem = T> + DataMut,
        Table: NttTable<ValueT = T>,
    {
        let p = result.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.transform_slice(p)
    }

    /// Performs a multiplication on the `self` [`Ntru<S>`] with another `ntt_polynomial` [`NttPolynomial<A>`],
    /// store the result into `result` [`NttNtru<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttNtru<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let p = result.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.transform_slice(p);
        NttPolynomial(p).mul_assign(ntt_poly, modulus);
    }
}

impl<S, T> Ntru<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: FieldContext<T>,
    {
        ArrayBase(self.as_mut()).mul_scalar_assign(scalar, modulus);
    }

    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        ArrayBase(self.as_mut()).mul_factor_assign(factor, modulus);
    }

    /// Transforms `self` to ntt form.
    #[inline]
    pub fn into_ntt_form<Table>(mut self, ntt_table: &Table) -> NttNtru<S>
    where
        Table: NttTable<ValueT = T>,
    {
        ntt_table.transform_slice(self.as_mut());
        NttNtru::new(self.0)
    }
}
