use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, FullComplex64FftTable};
use primus_lattice::context::tfhe::TfheFftContext;
use primus_lattice::ggsw::Ggsw;
use primus_lattice::ggsw::fourier::FourierGgswOwned;
use primus_lattice::glwe::Glwe;
use primus_lattice::tfhe::external_product::external_product_to;

// ---------------------------------------------------------------------------
// Naive coefficient-domain external product (reference, u32 only)
// ---------------------------------------------------------------------------

/// Naive coefficient-domain external product for u32: decomposes each input
/// component, multiplies by the coefficient GGSW key, and accumulates.
fn naive_external_product_u32(
    input: &Glwe<Vec<u32>>,
    ggsw_coeff: &Ggsw<Vec<u32>>,
    output: &mut Glwe<Vec<u32>>,
    basis: &ApproxSignedBasis<u32>,
    glwe_dimension: usize,
    poly_len: usize,
) {
    let total_components = glwe_dimension + 1;
    let level = basis.decompose_length();
    let glwe_len = total_components * poly_len;
    let glev_len = level * glwe_len;

    output.set_zero();

    let mut carries = vec![false; poly_len];
    let mut decomposed = vec![0u32; poly_len];

    for input_component in 0..total_components {
        let coeff_offset = input_component * poly_len;
        let coeff_poly = &input.as_ref()[coeff_offset..coeff_offset + poly_len];

        basis.init_carry_slice(coeff_poly, &mut carries);

        for (level_idx, decomposer) in basis.decompose_iter().enumerate() {
            decomposer.decompose_slice_to(coeff_poly, &mut decomposed, &mut carries);

            for output_component in 0..total_components {
                let out_offset = output_component * poly_len;
                let out_poly = &mut output.as_mut()[out_offset..out_offset + poly_len];

                let key_offset =
                    input_component * glev_len + level_idx * glwe_len + output_component * poly_len;
                let key_poly = &ggsw_coeff.as_ref()[key_offset..key_offset + poly_len];

                for j in 0..poly_len {
                    // Interpret each torus value as centered i32, do arithmetic in i64
                    let s = decomposed[j] as i32 as i64;
                    let g = key_poly[j] as i32 as i64;
                    let prod = s.wrapping_mul(g);
                    let old = out_poly[j] as i32 as i64;
                    let sum = old.wrapping_add(prod);
                    out_poly[j] = (sum as i32) as u32;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn external_product_smoke_test() {
    let log_n = 3;
    let fft = FullComplex64FftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    // Parameters: k=1, level=2
    let glwe_dimension = 1; // mask count k
    let total_components = glwe_dimension + 1; // k + 1 = 2
    let level = 2;

    let glwe_len = total_components * poly_len; // 2 * 8 = 16
    let glev_len = level * glwe_len; // 2 * 16 = 32
    let ggsw_len = total_components * glev_len; // 2 * 32 = 64

    // Create basis: modulus=None (power-of-2), log_basis=4 (B=16)
    let basis = ApproxSignedBasis::<u32>::new(None, 4, Some(level));

    // Create coefficient GGSW key with small values
    let ggsw_coeff: Vec<u32> = (0..ggsw_len).map(|i| ((i % 7) as i32 - 3) as u32).collect();
    let ggsw_coeff = Ggsw::new(ggsw_coeff);

    // Convert to Fourier
    let fourier_glwe_len = total_components * fourier_len; // 2 * 8 = 16
    let fourier_glev_len = level * fourier_glwe_len; // 2 * 16 = 32
    let fourier_ggsw_len = total_components * fourier_glev_len; // 2 * 32 = 64
    let mut fourier_key = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw_coeff.write_fourier_form(&mut fourier_key, &fft);

    // Create input GLWE
    let input: Vec<u32> = (0..glwe_len).map(|i| ((i as i32 % 5) - 2) as u32).collect();
    let input_glwe = Glwe::new(input);

    // External product (FFT-based)
    let mut ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    let mut output_fft = Glwe::<Vec<u32>>::zero(glwe_len);
    external_product_to(
        &input_glwe,
        &fourier_key,
        &mut output_fft,
        &basis,
        &fft,
        &mut ctx,
        glwe_dimension,
    );

    // Naive coefficient-domain reference
    let mut output_naive = Glwe::<Vec<u32>>::zero(glwe_len);
    naive_external_product_u32(
        &input_glwe,
        &ggsw_coeff,
        &mut output_naive,
        &basis,
        glwe_dimension,
        poly_len,
    );

    assert_eq!(
        output_fft.as_ref(),
        output_naive.as_ref(),
        "FFT-based external product must match naive coefficient reference"
    );
}

#[test]
fn external_product_zero_input() {
    let log_n = 2;
    let fft = FullComplex64FftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let glwe_dimension = 1; // mask count k = 1
    let total_components = glwe_dimension + 1; // = 2
    let level = 1;
    let glwe_len = total_components * poly_len;
    let fourier_glwe_len = total_components * fourier_len;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = total_components * fourier_glev_len;

    let basis = ApproxSignedBasis::<u32>::new(None, 8, Some(level));

    // Arbitrary Fourier key
    let mut key = FourierGgswOwned::zero(fourier_ggsw_len);
    key.as_mut()
        .fill_with(|| num_complex::Complex64::new(1.0, 0.0));

    let input = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut output = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);

    external_product_to(
        &input,
        &key,
        &mut output,
        &basis,
        &fft,
        &mut ctx,
        glwe_dimension,
    );

    // Zero input should produce zero output (all zero coefficients → all zero decomposed digits)
    for &v in output.as_ref() {
        assert_eq!(v, 0u32);
    }
}

#[test]
fn context_sizes() {
    let poly_len = 1024;
    let fourier_len = 1024;
    let glwe_dimension = 2; // k = 2, total = 3

    let ctx = TfheFftContext::<u32>::new(poly_len, fourier_len, glwe_dimension);
    assert_eq!(ctx.carries.len(), poly_len);
    assert_eq!(ctx.decomposed_poly.len(), poly_len);
    assert_eq!(ctx.decomposed_fourier.len(), fourier_len);
    // k + 1 = 3
    assert_eq!(
        ctx.fourier_accumulator.len(),
        (glwe_dimension + 1) * fourier_len
    );

    let mut ctx = ctx;
    ctx.resize(512, 256, 3); // k=3, total=4
    assert_eq!(ctx.carries.len(), 512);
    assert_eq!(ctx.decomposed_poly.len(), 512);
    assert_eq!(ctx.decomposed_fourier.len(), 256);
    assert_eq!(ctx.fourier_accumulator.len(), (3 + 1) * 256);
}
