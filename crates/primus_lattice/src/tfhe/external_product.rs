use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, TorusFftValue};
use primus_poly::FourierPolynomial;

use crate::context::tfhe::TfheFftContext;
use crate::ggsw::fourier::FourierGgsw;
use crate::glwe::fourier::FourierGlwe;
use crate::tfhe::TorusGlwe;

/// TFHE external product: `output = input ⊡ key` in the Fourier domain.
///
/// Decomposes each polynomial of the input GLWE into signed digits, forward-FFTs
/// each digit, multiplies by the corresponding Fourier GGSW row/level, and
/// accumulates in the Fourier domain before inverse-FFT back to torus
/// coefficients.
///
/// # GLWE dimension convention
///
/// `glwe_dimension` is the count of *mask* polynomials (`k`).  The total
/// number of polynomials in a GLWE ciphertext is `glwe_dimension + 1`
/// (k mask + 1 body).  This matches [`Lwe::dimension()`](crate::lwe::Lwe::dimension).
///
/// # Shape requirements
///
/// - `input`: `(glwe_dimension + 1) * poly_length` torus values
/// - `key`: `(glwe_dimension + 1) * level * (glwe_dimension + 1) * fourier_length` complex values
/// - `output`: `(glwe_dimension + 1) * poly_length` torus values
pub fn external_product_to<T, Table, A, B, C>(
    input: &TorusGlwe<A>,
    key: &FourierGgsw<B>,
    output: &mut TorusGlwe<C>,
    basis: &ApproxSignedBasis<T>,
    fft: &Table,
    context: &mut TfheFftContext<T>,
    glwe_dimension: usize,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: RawData<Elem = T> + Data,
    B: RawData<Elem = Complex64> + Data,
    C: RawData<Elem = T> + DataMut,
{
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let level = basis.decompose_length();
    // Total polynomials = k mask + 1 body
    let total_components = glwe_dimension + 1;

    // Zero the accumulator
    context.fourier_accumulator.fill(Complex64::new(0.0, 0.0));

    // Process each input component (a1..ak, b), aligned with GGSW rows:
    let glwe_fourier_len = total_components * fourier_len;
    let glev_len = level * glwe_fourier_len;

    for (coeff_poly, key_row) in input.iter_poly(poly_len).zip(key.iter_glev(glev_len)) {
        // Step 1: extract initial carry bits
        basis.init_carry_slice(coeff_poly.0, &mut context.carries);

        // Step 2: for each decomposition level, aligned with key GLev levels
        for (decomposer, key_glwe) in basis
            .decompose_iter()
            .zip(key_row.iter_glwe(glwe_fourier_len))
        {
            decomposer.decompose_slice_to(
                coeff_poly.0,
                &mut context.decomposed_poly,
                &mut context.carries,
            );

            // Forward FFT the decomposed polynomial
            fft.forward_torus_slice(&context.decomposed_poly, &mut context.decomposed_fourier);

            let decomposed_poly = FourierPolynomial::new(context.decomposed_fourier.as_slice());
            let mut acc_glwe = FourierGlwe::new(context.fourier_accumulator.as_mut_slice());

            // Step 3: accumulator += decomposed * key_glwe
            acc_glwe.add_mul_fourier_poly_assign(&decomposed_poly, &key_glwe);
        }
    }

    // Inverse FFT: accumulator → output GLWE
    let acc_glwe = FourierGlwe::new(context.fourier_accumulator.as_slice());
    acc_glwe.write_torus_form(output, fft);
}
