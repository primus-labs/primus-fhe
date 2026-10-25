//! GGSW external products in the DCRT domain.

use primus_data::{Data, DataMut};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::ggsw::DcrtGgsw;
use crate::glwe::{CrtGlwe, DcrtGlwe};
use crate::workspace::DcrtGlevMulWorkspace;

impl<S, T> DcrtGgsw<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Computes the external product of this DCRT GGSW and a CRT GLWE `input`,
    /// overwriting `output` in the DCRT domain.
    ///
    /// # Correctness
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    ///
    /// Let `size = workspace.size()`, `N = table.poly_length().get()`,
    /// and `m = rns_base.moduli_count()`.
    /// The bound size must match `N`, `m`, the GLWE dimension, and
    /// `basis.level_count().get()`; `workspace.is_compatible(size, rns_base)`
    /// must hold. The table uses the base's modulus order and the gadget
    /// uses its evaluation order and `basis.decomposer_iter()` level order.
    /// CRT/DCRT values must be canonical residues.
    /// Input and output each have `size.rns_glwe_size().rns_glwe_len()`
    /// elements, and the gadget has `size.rns_ggsw_len()` evaluations in
    /// row/level/component/modulus order under a compatible key. Output is
    /// cleared before accumulation; scratch needs no manual reset.
    pub fn external_product_to<M, Table, A, B>(
        &self,
        input: &CrtGlwe<A>,
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
        let rns_poly_len = table.rns_poly_len();
        let dcrt_glev_len = basis.level_count().get() * input.as_ref().len();

        output.set_zero();

        self.iter_dcrt_glev(dcrt_glev_len)
            .zip(input.iter_crt_poly(rns_poly_len))
            .for_each(|(dcrt_glev, crt_poly)| {
                output.add_dcrt_glev_mul_crt_polynomial_assign(
                    &dcrt_glev, &crt_poly, basis, table, rns_base, workspace,
                );
            });
    }
}
