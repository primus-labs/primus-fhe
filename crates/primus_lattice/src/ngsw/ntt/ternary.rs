//! Ternary encrypted rotations using one external product.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_reduce::FieldContext;

use crate::ntru::{Ntru, accumulate_ntt_gadget_product};
use crate::workspace::NttNtruCmuxWorkspace;

use super::NttNgsw;

impl<S, T> NttNgsw<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Rotates `input` by an encrypted ternary multiple of `exponent`.
    ///
    /// `self` and `negative` encrypt mutually exclusive bits `s⁺` and `s⁻`.
    /// For `s = s⁺ - s⁻`, the ideal output is `X^(exponent * s) * input`.
    /// This uses one external product:
    /// `output = input + (self - X^-exponent * negative) ⊠ ((X^exponent - 1) * input)`.
    /// Decomposition error and noise need not match two successive binary CMUXes;
    /// both control encryptions contribute noise even for `s=0`.
    ///
    /// # Correctness
    ///
    /// Both controls, input, output, basis, modulus and table must satisfy
    /// [`Self::external_product_to`] with `workspace.poly_length()`; each control
    /// has `workspace.level_count().get()` levels matching `basis`.
    /// Control bits must be mutually exclusive (unchecked), under the input's
    /// NTRU key. Independent control encryptions are required for the usual
    /// noise estimate.
    ///
    /// `exponent` is already quantized into `0..2N`. Its negative is derived
    /// modulo `2N`, not by separately quantizing a negated LWE coefficient.
    /// Output is overwritten with canonical coefficient-domain values without
    /// allocation or reset. A public zero exponent copies `input` exactly.
    ///
    /// # Panics
    /// Zero-exponent copying panics if input and output lengths differ.
    /// For nonzero exponents, a table/workspace polynomial-length mismatch panics
    /// when preparing the monomial factor, before output writes.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep controls, operands, basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_ternary_monomial_to<M, Table, A, B, C>(
        &self,
        negative: &NttNgsw<A>,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruCmuxWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length().get();
        let control_length = workspace.combined_control.len();
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(basis.level_count().get(), workspace.level_count().get());
        debug_assert_eq!(self.as_ref().len(), control_length);
        debug_assert_eq!(negative.as_ref().len(), control_length);
        debug_assert_eq!(input.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);
        if exponent == 0 {
            output.as_mut().copy_from_slice(input.as_ref());
            return;
        }

        let inverse_exponent = 2 * poly_length - exponent;
        // Control combination and decomposition run sequentially, so the
        // monomial factor can reuse the external-product digit buffer.
        let mut product = workspace.external_product.as_mut();
        self.sub_mul_monomial_to(
            negative,
            inverse_exponent,
            &mut NttNgsw(workspace.combined_control.as_mut_slice()),
            modulus,
            ntt,
            product.decomposed_ntt,
        );

        // Output first holds (X^a-1)C, so the external product accumulates in
        // its own buffer until decomposition has consumed the difference.
        input.mul_monomial_sub_one_to(exponent, output, modulus);
        product.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            workspace.combined_control.as_ref(),
            output.as_ref(),
            basis,
            modulus,
            ntt,
            &mut product,
        );
        product.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
