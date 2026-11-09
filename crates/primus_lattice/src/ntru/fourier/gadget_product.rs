//! Shared NLev and NGSW decomposition, transform, and accumulation kernels.
//!
//! NLEV and NGSW have different encrypted phases but share this arithmetic and
//! level layout. Wrappers choose the accumulator, clear it once per operation,
//! and convert it after the last product. These kernels only add one product.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_poly::{FourierPolynomial, FourierPolynomialIter};

use crate::workspace::FourierNtruExternalProductWorkspaceRefMut;

/// Adds the gadget product of `gadget` and `input` to the existing Fourier accumulator.
/// This does not clear the accumulator; the caller must initialize it first.
///
/// # Correctness
///
/// Input contains `N = workspace.poly_length()` canonical coefficients. The
/// gadget has `basis.level_count().get()` complete levels in decomposition
/// order, each of length `N / 2` in the FFT table's normalized torus
/// representation. The basis uses the native modulus, and FFT/workspace
/// polynomial lengths and packing agree. The selected accumulator has `N / 2`
/// complex values and is disjoint from the input and decomposition scratch.
/// These conditions are caller obligations, with selected debug diagnostics.
pub(crate) fn accumulate_fourier_gadget_product<T, Table>(
    gadget: &[Complex64],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    workspace: &mut FourierNtruExternalProductWorkspaceRefMut<'_, T>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let poly_length = workspace.poly_length();
    let fourier_length = fft.fourier_length();

    debug_assert_eq!(fft.poly_length().get(), poly_length);
    debug_assert_eq!(fourier_length, poly_length / 2);
    debug_assert_eq!(basis.modulus(), None);
    debug_assert_eq!(input.len(), poly_length);
    debug_assert_eq!(gadget.len(), basis.level_count().get() * fourier_length);

    // Carries belong to this input's signed decomposition, not the accumulated
    // sum. Reinitialize them for each product, then carry across its levels.
    basis.init_carry_slice(input, workspace.carries);

    for (decomposer, key_level) in basis
        .decomposer_iter()
        .zip(FourierPolynomialIter::new(gadget, fourier_length))
    {
        decomposer.decompose_slice_to(input, workspace.decomposed_poly, workspace.carries);
        fft.forward_as_integer(workspace.decomposed_poly, workspace.decomposed_fourier);
        FourierPolynomial(workspace.fourier_accumulator.as_mut()).add_mul_assign(
            &FourierPolynomial(&*workspace.decomposed_fourier),
            &key_level,
        );
    }
}
