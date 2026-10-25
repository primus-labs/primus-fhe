//! GGSW-controlled conditional multiplexers in the Fourier domain.

use core::borrow::Borrow;

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;

use crate::glwe::TorusGlwe;
use crate::workspace::FourierGlweExternalProductWorkspace;

use super::FourierGgsw;

impl<S> FourierGgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` is a Fourier GGSW encryption of a bit. A control bit of zero
    /// selects `ct0`, while a control bit of one selects `ct1`. The GLWE inputs
    /// and output use the implicit native torus modulus and coefficient form.
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and workspace must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `workspace.size().glwe_size().glwe_len()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or workspace reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    pub fn cmux_to<T, Table, B, C, D>(
        &self,
        ct0: &TorusGlwe<B>,
        ct1: &TorusGlwe<C>,
        output: &mut TorusGlwe<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let glwe_len = workspace.size().glwe_size().glwe_len();
        debug_assert_eq!(ct0.as_ref().len(), glwe_len);
        debug_assert_eq!(ct1.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);

        ct1.sub_to(ct0, output, NativeModulus::new());
        workspace.fourier_accumulator.set_zero();
        self.as_view().accumulate_external_product(
            output.as_view(),
            basis,
            fft,
            &mut workspace.as_mut(),
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(ct0, NativeModulus::new());
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
    /// Products are summed in the Fourier domain before one inverse transform
    /// and torus rounding; rounding each product separately can differ.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the reported iterator counts differ.
    /// Incorrect lengths may panic but are not systematically validated.
    /// A panicking iterator, item conversion, or later length failure can leave
    /// output holding an intermediate difference and scratch holding a partial
    /// sum. Discard the result; a valid call can reuse the workspace without reset.
    pub fn cmux_k_to<'a, T, Table, I, J>(
        controls: I,
        default: TorusGlwe<&[T]>,
        candidates: J,
        mut output: TorusGlwe<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        I: IntoIterator<Item: Borrow<Self>, IntoIter: ExactSizeIterator>,
        J: IntoIterator<Item: Into<TorusGlwe<&'a [T]>>, IntoIter: ExactSizeIterator>,
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

        workspace.fourier_accumulator.set_zero();
        // Round only after summing all products. Rounding per pair would
        // change the approximation error and traverse the coefficients again.
        for (control, candidate) in controls.zip(candidates) {
            let candidate = candidate.into();
            debug_assert_eq!(candidate.as_ref().len(), glwe_len);
            candidate.sub_to(&default, &mut output, NativeModulus::new());
            let control: &Self = control.borrow();
            control.as_view().accumulate_external_product(
                output.as_view(),
                basis,
                fft,
                &mut workspace.as_mut(),
            );
        }
        workspace
            .fourier_accumulator
            .write_torus_form(&mut output, fft);
        output.add_assign(&default, NativeModulus::new());
    }

    /// Computes `output = input + self external_product
    /// (input * (X^exponent - 1))` for the native-torus Fourier backend.
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
    pub fn cmux_monomial_to<T, Table, B, C>(
        &self,
        input: &TorusGlwe<B>,
        exponent: usize,
        output: &mut TorusGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = workspace.size().glwe_size().poly_length().get();

        input.mul_monomial_sub_one_to(exponent, output, poly_length, NativeModulus::new());
        workspace.fourier_accumulator.set_zero();
        self.as_view().accumulate_external_product(
            output.as_view(),
            basis,
            fft,
            &mut workspace.as_mut(),
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(input, NativeModulus::new());
    }
}
