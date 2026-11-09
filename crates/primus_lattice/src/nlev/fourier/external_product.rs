//! NLev external products using the shared scalar NTRU gadget kernels.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_poly::Polynomial;

use crate::ntru::{FourierNtru, Ntru, accumulate_fourier_gadget_product};
use crate::workspace::FourierNtruExternalProductWorkspace;

use super::FourierNlev;

impl<S> FourierNlev<S>
where
    S: Data<Elem = Complex64>,
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
    /// `self` contains exactly `L * N / 2` complex values, grouped
    /// by level in `basis.decomposer_iter()` order. The basis must be the
    /// one used to construct the gadget ciphertext.
    /// `basis` must use the implicit native modulus (`basis.modulus() == None`).
    /// The FFT engine must have polynomial length `N` and Fourier length
    /// `N / 2`; gadget values must use its packing and normalized torus scale.
    /// Output is overwritten and workspace scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        debug_assert_eq!(output.as_ref().len(), workspace.poly_length().get());
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
    }

    /// Computes the gadget product directly in this key's Fourier representation.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::external_product_to`]'s input, key, basis, table and
    /// workspace contracts. Output contains exactly `N / 2` complex values at
    /// torus scale. It is used directly as the accumulator, without an inverse
    /// transform or torus rounding; later conversion requires the same FFT table.
    ///
    /// # Panics
    /// Panics if the output length is not `workspace.poly_length().fourier_poly_len()`.
    pub fn external_product_fourier_to<T, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
        output: &mut FourierNtru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = Complex64>,
    {
        assert_eq!(
            output.as_ref().len(),
            workspace.poly_length().fourier_poly_len(),
            "external-product output length mismatch"
        );
        let mut workspace = workspace.as_mut_with_accumulator(output);
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
    }
}
