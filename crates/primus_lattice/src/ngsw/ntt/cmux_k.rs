//! Multi-way NGSW CMux with one transform-domain sum.
//!
//! Every difference uses the same default ciphertext. The output buffer holds
//! each difference while the workspace retains the sum; adding the default once
//! after inversion selects it when all controls encrypt zero.
//! Batch counts and fixed buffers are checked first; each streamed pair is checked
//! before its difference is written. No iterator cloning or batch allocation is needed.

use core::borrow::Borrow;

use primus_data::Data;
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
    /// `as_mut_view()` for owned default and output ciphertexts.
    /// Callers constructing chunk iterators must exclude incomplete trailing objects.
    /// Output is overwritten and workspace scratch needs no manual reset. Products
    /// are summed in the transform domain before a single inverse transform.
    ///
    /// # Panics
    ///
    /// Panics on unequal reported iterator counts or incorrect object lengths.
    /// Counts and default/output lengths are checked before writes; individual
    /// controls/candidates are checked together before processing each pair.
    /// An invalid pair or a panicking iterator can leave output holding a previous
    /// difference and scratch holding a partial sum. Control-length overflow is
    /// rejected before writes. Reusing the workspace in a valid call needs no reset.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_k_to<'a, M, Table, I, J>(
        controls: I,
        default: Ntru<&[T]>,
        candidates: J,
        mut output: Ntru<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        I: IntoIterator<Item: Borrow<Self>, IntoIter: ExactSizeIterator>,
        J: IntoIterator<Item: Into<Ntru<&'a [T]>>, IntoIter: ExactSizeIterator>,
    {
        let controls = controls.into_iter();
        let candidates = candidates.into_iter();
        assert_eq!(
            controls.len(),
            candidates.len(),
            "CMUX requires one control per candidate"
        );
        let poly_length = workspace.poly_length().get();
        assert_eq!(
            default.as_ref().len(),
            poly_length,
            "CMUX default length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            poly_length,
            "CMUX output length mismatch"
        );

        if candidates.len() == 0 {
            output.as_mut().copy_from_slice(default.as_ref());
            return;
        }

        let control_len = basis
            .level_count()
            .get()
            .checked_mul(poly_length)
            .expect("CMUX control length overflow");
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        // Keep default unchanged: each decomposed difference is relative to
        // the same c_0. Clear once above and invert only after the entire sum.
        for (control, candidate) in controls.zip(candidates) {
            let candidate = candidate.into();
            assert_eq!(
                candidate.as_ref().len(),
                poly_length,
                "CMUX candidate length mismatch"
            );
            let control: &Self = control.borrow();
            assert_eq!(
                control.as_ref().len(),
                control_len,
                "CMUX control length mismatch"
            );
            candidate.sub_to(&default, &mut output, modulus);
            accumulate_ntt_gadget_product(
                control.as_ref(),
                output.as_ref(),
                basis,
                modulus,
                ntt,
                &mut workspace,
            );
        }
        workspace.ntt_accumulator.write_coeff_form(&mut output, ntt);
        output.add_assign(&default, modulus);
    }
}
