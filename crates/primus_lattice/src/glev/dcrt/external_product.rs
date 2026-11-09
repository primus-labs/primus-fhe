//! DCRT GLev products with CRT and BigUint coefficient polynomials.

use primus_data::{Data, DataMut};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{BigUintPolynomial, CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{
    glwe::DcrtGlwe,
    workspace::{DcrtGlevMulWorkspace, DcrtGlevMulWorkspaceRefMut},
};

use super::DcrtGlev;

impl<S, T> DcrtGlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Multiplies this DCRT GLEV with a CRT-domain polynomial, storing the output into `output`.
    ///
    /// # Correctness
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    /// `workspace` must support the GLev layout and the current RNS limb
    /// width; the table must match its polynomial length and ordered RNS base.
    /// The output is overwritten; scratch does not require a manual reset.
    ///
    /// Let `size = workspace.size()`, `N = table.poly_length().get()`,
    /// `m = rns_base.moduli_count()`, and `w = rns_base.big_uint_value_len()`.
    /// The bound size must match `N`, `m`, the GLWE dimension, and
    /// `basis.level_count().get()`; `workspace.is_compatible(size, rns_base)`
    /// must hold. The table uses the base's modulus order and the gadget
    /// uses its evaluation order and `basis.decomposer_iter()` level order.
    /// CRT/DCRT values must be canonical residues.
    /// The GLev contains exactly `size.rns_glev_len()` evaluations and the
    /// GLWE output/accumulator exactly `size.rns_glwe_size().rns_glwe_len()`.
    /// The polynomial contains `N * m` coefficients grouped by modulus.
    ///
    /// # Panics
    ///
    /// The RNS recomposition boundary panics if the CRT polynomial length
    /// is not `N * m` or the workspace's BigUint/scratch lengths do not match
    /// `N * w` and `m`. Other compatibility requirements are not fully checked.
    pub fn mul_crt_polynomial_to<M, Table, A, B>(
        &self,
        crt_poly: &CrtPolynomial<A>,
        output: &mut DcrtGlwe<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        workspace: &mut DcrtGlevMulWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        output.set_zero();
        output.add_dcrt_glev_mul_crt_polynomial_assign(
            self, crt_poly, basis, table, rns_base, workspace,
        );
    }

    /// Multiplies this DCRT GLEV with a BigUint-domain polynomial, storing the output into `output`.
    ///
    /// # Correctness
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    /// `workspace` must support the GLev layout and the current RNS limb
    /// width; the table must match its polynomial length and ordered RNS base.
    /// The output is overwritten; scratch does not require a manual reset.
    ///
    /// Let `size = workspace.size()`, `N = table.poly_length().get()`,
    /// `m = rns_base.moduli_count()`, and `w = rns_base.big_uint_value_len()`.
    /// The bound size must match `N`, `m`, the GLWE dimension, and
    /// `basis.level_count().get()`; `workspace.is_compatible(size, rns_base)`
    /// must hold. The table uses the base's modulus order and the gadget
    /// uses its evaluation order and `basis.decomposer_iter()` level order.
    /// CRT/DCRT values must be canonical residues.
    /// The GLev contains exactly `size.rns_glev_len()` evaluations and the
    /// GLWE output/accumulator exactly `size.rns_glwe_size().rns_glwe_len()`.
    /// The polynomial contains `N * w` little-endian limbs grouped by
    /// coefficient, each representing a value in `[0, Q)`, where `Q` is the
    /// product of the RNS moduli.
    pub fn mul_big_uint_polynomial_to<M, Table, A, B>(
        &self,
        big_uint_poly: &BigUintPolynomial<A>,
        output: &mut DcrtGlwe<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        workspace: &mut DcrtGlevMulWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        output.set_zero();
        output.add_dcrt_glev_mul_big_uint_polynomial_assign(
            self,
            big_uint_poly,
            basis,
            table,
            rns_base,
            workspace,
        );
    }
}

impl<S, T> DcrtGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Accumulates `self += dcrt_glev * crt_poly` without clearing `self`.
    ///
    /// # Correctness
    ///
    /// The operands, basis, table, RNS base, and workspace must satisfy
    /// [`DcrtGlev::mul_crt_polynomial_to`], with `self` as its output.
    /// `self` must already contain canonical residues under the same key and
    /// ordered RNS base. Scratch is initialized as needed; no reset is required.
    ///
    /// # Panics
    ///
    /// The same RNS recomposition length checks as
    /// [`DcrtGlev::mul_crt_polynomial_to`] apply.
    pub fn add_dcrt_glev_mul_crt_polynomial_assign<M, Table, A, B>(
        &mut self,
        dcrt_glev: &DcrtGlev<A>,
        crt_poly: &CrtPolynomial<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        workspace: &mut DcrtGlevMulWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        let poly_length = table.poly_length().get();
        let dcrt_glwe_len = self.0.len();

        let size = workspace.size();
        debug_assert!(
            workspace.is_compatible(size, rns_base),
            "incompatible DCRT workspace"
        );
        debug_assert_eq!(size.rns_glwe_size().poly_length().get(), poly_length);
        debug_assert_eq!(size.rns_glwe_size().rns_glwe_len(), dcrt_glwe_len);
        debug_assert_eq!(size.level_count().get(), basis.level_count().get());

        debug_assert_eq!(
            dcrt_glev.as_ref().len(),
            dcrt_glwe_len * basis.level_count().get()
        );
        let scratch = workspace.as_mut();

        rns_base.compose_big_uint_values_to(
            crt_poly.as_ref(),
            scratch.adjust_big_uint_values,
            poly_length,
            scratch.compose_buffer,
        );

        basis.init_value_carry_slice_assign(scratch.adjust_big_uint_values, scratch.carries);

        self.as_mut_view().add_decomposed_glev_product_assign(
            dcrt_glev.as_view(),
            basis,
            table,
            rns_base,
            scratch,
        );
    }

    /// Accumulates `self += dcrt_glev * big_uint_poly` without clearing `self`.
    ///
    /// # Correctness
    ///
    /// The operands, basis, table, RNS base, and workspace must satisfy
    /// [`DcrtGlev::mul_big_uint_polynomial_to`], with `self` as its output.
    /// `self` must already contain canonical residues under the same key and
    /// ordered RNS base. Scratch is initialized as needed; no reset is required.
    pub fn add_dcrt_glev_mul_big_uint_polynomial_assign<M, Table, A, B>(
        &mut self,
        dcrt_glev: &DcrtGlev<A>,
        big_uint_poly: &BigUintPolynomial<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        workspace: &mut DcrtGlevMulWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        let poly_length = table.poly_length().get();
        let big_uint_value_len = rns_base.big_uint_value_len();
        let big_uint_poly_len = big_uint_poly.len();

        debug_assert_eq!(big_uint_poly_len, big_uint_value_len * poly_length);

        let dcrt_glwe_len = self.0.len();

        let size = workspace.size();
        debug_assert!(
            workspace.is_compatible(size, rns_base),
            "incompatible DCRT workspace"
        );
        debug_assert_eq!(size.rns_glwe_size().poly_length().get(), poly_length);
        debug_assert_eq!(size.rns_glwe_size().rns_glwe_len(), dcrt_glwe_len);
        debug_assert_eq!(size.level_count().get(), basis.level_count().get());

        debug_assert_eq!(
            dcrt_glev.as_ref().len(),
            dcrt_glwe_len * basis.level_count().get()
        );
        let scratch = workspace.as_mut();

        basis.init_value_carry_slice_to(
            big_uint_poly.as_slice(),
            scratch.adjust_big_uint_values,
            scratch.carries,
        );

        self.as_mut_view().add_decomposed_glev_product_assign(
            dcrt_glev.as_view(),
            basis,
            table,
            rns_base,
            scratch,
        );
    }
}

impl<T: FheUint> DcrtGlwe<&mut [T]> {
    /// Accumulates gadget levels after the input polynomial has been adjusted.
    ///
    /// The caller initializes `scratch.adjust_big_uint_values` and `scratch.carries`
    /// with `basis`. Layout, modulus order, digit-lift bounds, and the initialized
    /// output satisfy the public product contract. Other scratch is overwritten;
    /// this kernel neither clears the output nor repeats boundary checks.
    fn add_decomposed_glev_product_assign<M, Table>(
        &mut self,
        dcrt_glev: DcrtGlev<&[T]>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        scratch: DcrtGlevMulWorkspaceRefMut<'_, T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = table.poly_length().get();
        let dcrt_glwe_len = self.as_ref().len();
        let basis_value = basis.basis_value();
        let moduli = rns_base.moduli();
        let DcrtGlevMulWorkspaceRefMut {
            adjust_big_uint_values,
            decomposed_unsigned_values,
            carries,
            multi_residues,
            compose_buffer: _,
        } = scratch;

        for (dcrt_glwe, decomposer) in dcrt_glev
            .iter_dcrt_glwe(dcrt_glwe_len)
            .zip(basis.decomposer_iter())
        {
            decomposer.decompose_radix_slice_to(
                adjust_big_uint_values.as_ref(),
                decomposed_unsigned_values,
                carries,
            );

            rns_base.wrapping_decompose_small_values_to(
                decomposed_unsigned_values.as_ref(),
                multi_residues,
                basis_value,
            );

            table.transform_slice(multi_residues);

            self.add_mul_dcrt_polynomial_assign(
                &dcrt_glwe,
                &DcrtPolynomial(&*multi_residues),
                poly_length,
                moduli,
            );
        }
    }
}
