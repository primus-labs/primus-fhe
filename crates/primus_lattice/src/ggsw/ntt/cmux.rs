//! GGSW-controlled conditional multiplexers in the NTT domain.

use core::borrow::Borrow;

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::glwe::Glwe;
use crate::workspace::NttGlweExternalProductWorkspace;

use super::NttGgsw;

impl<S> NttGgsw<S>
where
    S: RawData,
    S::Elem: FheUint,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` is an NTT GGSW encryption of a bit. A control bit of zero selects
    /// `ct0`, while a control bit of one selects `ct1`. Every coefficient-domain
    /// GLWE coefficient must be reduced to `[0, q)`.
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and workspace must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `workspace.size().glwe_size().glwe_len()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or workspace reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_to<T, M, Table, B, C, D>(
        &self,
        ct0: &Glwe<B>,
        ct1: &Glwe<C>,
        output: &mut Glwe<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let glwe_len = workspace.size().glwe_size().glwe_len();
        debug_assert_eq!(ct0.as_ref().len(), glwe_len);
        debug_assert_eq!(ct1.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);

        ct1.sub_to(ct0, output, modulus);
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        self.as_view().accumulate_external_product(
            output.as_view(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(ct0, modulus);
    }

    /// Selects among `default` and `candidates` using encrypted control bits.
    ///
    /// This evaluates
    /// `default + sum_j controls[j] * (candidates[j] - default)`.
    ///
    /// `controls[j]` encrypts the bit selecting `candidates[j]`. At most one
    /// control bit may be nonzero. An all-zero control vector selects
    /// `default`; otherwise the unique nonzero bit selects its corresponding
    /// candidate.
    ///
    /// # Correctness
    ///
    /// Each control and every coefficient-domain input/output must satisfy
    /// [`Self::cmux_to`], using the same basis, table, and workspace layout.
    /// Controls and candidates have equal counts and matching order. Each
    /// control encrypts a bit, with at most one bit equal to one; bit values
    /// and exclusivity are not checked. Empty lists copy `default` exactly.
    /// Controls may be borrowed objects or semantic iterators over packed storage.
    /// Candidate items convert to shared views via `Into`; use `as_view()` and
    /// `as_mut_view()` for owned default and output ciphertexts. Chunk iterators
    /// must not omit incomplete trailing ciphertexts, and their reported counts
    /// must match the number of yielded items.
    /// Output is overwritten and workspace scratch needs no manual reset.
    /// Products are summed in the NTT domain before a single inverse transform.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the reported iterator counts differ.
    /// Incorrect lengths may panic but are not systematically validated.
    /// A panicking iterator, item conversion, or later length failure can leave
    /// output holding an intermediate difference and scratch holding a partial
    /// sum. Discard the result; a valid call can reuse the workspace without reset.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_k_to<'a, T, M, Table, I, J>(
        controls: I,
        default: Glwe<&[T]>,
        candidates: J,
        mut output: Glwe<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: Data<Elem = T>,
        I: IntoIterator<Item: Borrow<Self>, IntoIter: ExactSizeIterator>,
        J: IntoIterator<Item: Into<Glwe<&'a [T]>>, IntoIter: ExactSizeIterator>,
    {
        let controls = controls.into_iter();
        let candidates = candidates.into_iter();
        assert_eq!(
            controls.len(),
            candidates.len(),
            "CMUX requires one control per candidate"
        );
        let glwe_len = workspace.size().glwe_size().glwe_len();
        debug_assert_eq!(default.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);
        if candidates.len() == 0 {
            output.as_mut().copy_from_slice(default.as_ref());
            return;
        }

        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        // Each difference uses the same default; only the transformed sum
        // survives between pairs, so inversion and default addition happen once.
        for (control, candidate) in controls.zip(candidates) {
            let candidate = candidate.into();
            debug_assert_eq!(candidate.as_ref().len(), glwe_len);
            candidate.sub_to(&default, &mut output, modulus);
            let control: &Self = control.borrow();
            control.as_view().accumulate_external_product(
                output.as_view(),
                basis,
                modulus,
                ntt,
                &mut workspace,
            );
        }
        workspace.ntt_accumulator.write_coeff_form(&mut output, ntt);
        output.add_assign(&default, modulus);
    }

    /// Computes `output = input + self external_product
    /// (input * (X^exponent - 1))` for the NTT backend.
    ///
    /// This is the CMUX form used by blind rotation. `exponent` must belong to
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
    pub fn cmux_monomial_to<T, M, Table, B, C>(
        &self,
        input: &Glwe<B>,
        exponent: usize,
        output: &mut Glwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = workspace.size().glwe_size().poly_length().get();

        input.mul_monomial_sub_one_to(exponent, output, poly_length, modulus);
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        self.as_view().accumulate_external_product(
            output.as_view(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
