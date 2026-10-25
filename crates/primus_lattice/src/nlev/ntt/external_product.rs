//! NLev external products using the shared scalar NTRU gadget kernels.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

use crate::ntru::{Ntru, NttNtru, accumulate_ntt_gadget_product};
use crate::workspace::NttNtruExternalProductWorkspace;

use super::NttNlev;

impl<S, T> NttNlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Computes the gadget external product `polynomial odot self`.
    ///
    /// The output is a coefficient-domain scalar NTRU ciphertext. `basis`
    /// must be the decomposition basis used to construct this NLev ciphertext.
    ///
    /// # Correctness
    ///
    /// Let `N = workspace.poly_length().get()` and `L = basis.level_count().get()`.
    /// The polynomial input and output each contain exactly `N` coefficients.
    /// `self` contains exactly `L * N` evaluations, grouped
    /// by level in `basis.decomposer_iter()` order. The basis must be the
    /// one used to construct the gadget ciphertext.
    /// `basis`, `modulus`, and the NTT table must use the same modulus.
    /// The NTT polynomial length must be `N`, and gadget evaluations must
    /// use that table's order. Input and gadget values must be canonical residues.
    /// Output is overwritten and workspace scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    ///
    /// # Panics
    /// Panics before output writes if its length is not `workspace.poly_length().get()`.
    pub fn external_product_to<M, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        // Coefficients and NTT evaluations share storage. Accumulate into the
        // destination, then invert in place to avoid copying an entire polynomial.
        assert_eq!(
            output.as_ref().len(),
            workspace.poly_length().get(),
            "external-product output length mismatch"
        );
        let mut transformed = NttNtru(output.as_mut());
        let mut workspace = workspace.as_mut_with_accumulator(&mut transformed);
        workspace.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        ntt.inverse_transform_slice(workspace.ntt_accumulator.as_mut());
    }

    /// Computes the gadget product directly in this key's NTT representation.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::external_product_to`]'s input, key, basis, table and
    /// workspace contracts. Output contains exactly `N` canonical evaluations
    /// in the table's order. It is used directly as the accumulator, without a copy
    /// from the workspace or an inverse transform.
    ///
    /// # Panics
    /// Panics if the output length is not `workspace.poly_length().get()`.
    pub fn external_product_ntt_to<M, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
        output: &mut NttNtru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        assert_eq!(
            output.as_ref().len(),
            workspace.poly_length().get(),
            "external-product output length mismatch"
        );
        let mut workspace = workspace.as_mut_with_accumulator(output);
        workspace.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
    }
}
