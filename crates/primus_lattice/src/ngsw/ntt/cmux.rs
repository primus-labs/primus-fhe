//! NGSW-controlled conditional multiplexers in the NTT domain.
//!
//! The output buffer holds the coefficient difference during decomposition, so
//! these operations use the workspace-owned accumulator instead of borrowing output.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::ntru::{Ntru, accumulate_ntt_gadget_product};
use crate::workspace::NttNtruExternalProductWorkspace;

use super::NttNgsw;

impl<S, T> NttNgsw<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` encrypts the control bit. Zero selects `ct0`, and one selects
    /// `ct1`. Inputs and output are coefficient-domain NTRU ciphertexts.
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and workspace must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `workspace.poly_length()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or workspace reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_to<M, Table, B, C, D>(
        &self,
        ct0: &Ntru<B>,
        ct1: &Ntru<C>,
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length().get();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_to(ct0, output, modulus);
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(ct0, modulus);
    }

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    ///
    /// # Correctness
    ///
    /// The control, input, output, basis, table, and workspace must satisfy
    /// [`Self::cmux_to`]. Require `exponent < 2 * N`, where `N` is the
    /// workspace polynomial length. Bit zero selects `input`; bit one selects
    /// `input * X^exponent`. Output is overwritten; no reset is required.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_monomial_to<M, Table, B, C>(
        &self,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        input.mul_monomial_sub_one_to(exponent, output, modulus);
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
