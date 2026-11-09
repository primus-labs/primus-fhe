mod gadget_product;

pub(crate) use gadget_product::{
    accumulate_ntt_gadget_prepermuted_sum, accumulate_ntt_gadget_product,
};

use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::NttPolynomial;
use primus_reduce::FieldContext;

use super::Ntru;

/// A cryptographic structure for NTRU.
///
/// ## Structure of the `data`
///
/// |------h------|
///
/// where `h` is [`NttPolynomial`].
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Stored values must use the matching NTT table, modulus, and evaluation
/// order; a representation wrapper alone does not perform a transform.
#[derive(Clone)]
pub struct NttNtru<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(NttNtru);

impl_iters!(NttNtru);

impl_basic_operation_single_modulus!(NttNtru);
impl_neg_single_modulus!(NttNtru);
impl_mul_scalar_single_modulus!(NttNtru);
impl_mul_factor_single_modulus!(NttNtru);
impl_ntt_monomial!(NttNtru);

impl<S, T> NttNtru<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Transforms `self` to coefficient form and stores in `output`.
    ///
    /// # Correctness
    ///
    /// Storage must contain exactly one polynomial of `ntt_table.poly_length().get()`
    /// values, satisfying the selected transform's input range. The table
    /// modulus must match the ciphertext; inverse input must use that table's
    /// evaluation order and normalization. Output has the same length and is
    /// fully overwritten.
    ///
    /// # Panics
    ///
    /// Panics if input and output lengths differ.
    #[inline]
    pub fn write_coeff_form<Table, A>(&self, output: &mut Ntru<A>, ntt_table: &Table)
    where
        A: DataMut<Elem = T>,
        Table: NttTable<ValueT = T>,
    {
        let p = output.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.inverse_transform_slice(p);
    }

    /// Performs a modular multiplication on the `self` [`NttNtru<S>`] with another `polynomial` [`NttPolynomial`],
    /// stores the output into `output`.
    ///
    /// # Correctness
    ///
    /// Every operand contains exactly one polynomial of the same nonzero
    /// length in the same NTT order and modulus. Values must be canonical
    /// residues. Ciphertext keys must be compatible for accumulation;
    /// `*_assign` preserves the accumulator, while `*_to` overwrites output.
    #[inline]
    pub fn mul_ntt_polynomial_to<M, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        output: &mut NttNtru<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        NttPolynomial(self.as_ref()).mul_to(ntt_poly, &mut NttPolynomial(output.as_mut()), modulus);
    }
}

impl<S, T> NttNtru<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Transforms `self` to coefficient form.
    ///
    /// # Correctness
    ///
    /// Storage must contain exactly one polynomial of `ntt_table.poly_length().get()`
    /// values, satisfying the selected transform's input range. The table
    /// modulus must match the ciphertext; inverse input must use that table's
    /// evaluation order and normalization.
    #[inline]
    pub fn into_coeff_form<Table>(mut self, ntt_table: &Table) -> Ntru<S>
    where
        Table: NttTable<ValueT = T>,
    {
        ntt_table.inverse_transform_slice(self.as_mut());
        Ntru::new(self.0)
    }

    /// Performs a modular multiplication on the `self` [`NttNtru<S>`] with another `ntt_poly` [`NttPolynomial<A>`].
    ///
    /// # Correctness
    ///
    /// Every operand contains exactly one polynomial of the same nonzero
    /// length in the same NTT order and modulus. Values must be canonical
    /// residues. Ciphertext keys must be compatible for accumulation;
    /// `*_assign` preserves the accumulator, while `*_to` overwrites output.
    #[inline]
    pub fn mul_ntt_polynomial_assign<M, A>(&mut self, ntt_poly: &NttPolynomial<A>, modulus: M)
    where
        M: FieldContext<T>,
        A: Data<Elem = T>,
    {
        NttPolynomial(self.as_mut()).mul_assign(ntt_poly, modulus);
    }

    /// Performs `self += rhs * poly` in place, all in the NTT domain.
    ///
    /// # Correctness
    ///
    /// Every operand contains exactly one polynomial of the same nonzero
    /// length in the same NTT order and modulus. Values must be canonical
    /// residues. Ciphertext keys must be compatible for accumulation;
    /// `*_assign` preserves the accumulator, while `*_to` overwrites output.
    pub fn add_mul_ntt_polynomial_assign<M, A, B>(
        &mut self,
        rhs: &NttNtru<A>,
        poly: &NttPolynomial<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        NttPolynomial(self.as_mut()).add_mul_assign(&NttPolynomial(rhs.as_ref()), poly, modulus);
    }
}

impl<S, T> Ntru<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Transforms `self` to ntt form and stores in `output`.
    ///
    /// # Correctness
    ///
    /// Storage must contain exactly one polynomial of `ntt_table.poly_length().get()`
    /// values, satisfying the selected transform's input range. The table
    /// modulus must match the ciphertext; inverse input must use that table's
    /// evaluation order and normalization. Output has the same length and is
    /// fully overwritten.
    ///
    /// # Panics
    ///
    /// Panics if input and output lengths differ.
    #[inline]
    pub fn write_ntt_form<Table, A>(&self, output: &mut NttNtru<A>, ntt_table: &Table)
    where
        A: DataMut<Elem = T>,
        Table: NttTable<ValueT = T>,
    {
        let p = output.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.transform_slice(p)
    }

    /// Performs a multiplication on the `self` [`Ntru<S>`] with another `ntt_polynomial` [`NttPolynomial<A>`],
    /// store the output into `output` [`NttNtru<B>`].
    ///
    /// # Correctness
    ///
    /// Each coefficient polynomial must have `ntt_table.poly_length().get()` entries;
    /// `ntt_poly` must have exactly that length in the table's NTT order.
    /// The table, ciphertext, polynomial, and `modulus` must use the same
    /// modulus, and input values must be canonical residues. Output has the
    /// same component count and total length as `self` and is overwritten in
    /// NTT form, retaining the ciphertext key.
    ///
    /// # Panics
    ///
    /// Panics if input and output storage lengths differ.
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        output: &mut NttNtru<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let p = output.as_mut();
        p.copy_from_slice(self.as_ref());
        ntt_table.transform_slice(p);
        NttPolynomial(p).mul_assign(ntt_poly, modulus);
    }
}

impl<S, T> Ntru<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Transforms `self` to ntt form.
    ///
    /// # Correctness
    ///
    /// Storage must contain exactly one polynomial of `ntt_table.poly_length().get()`
    /// values, satisfying the selected transform's input range. The table
    /// modulus must match the ciphertext; inverse input must use that table's
    /// evaluation order and normalization.
    #[inline]
    pub fn into_ntt_form<Table>(mut self, ntt_table: &Table) -> NttNtru<S>
    where
        Table: NttTable<ValueT = T>,
    {
        ntt_table.transform_slice(self.as_mut());
        NttNtru::new(self.0)
    }
}
