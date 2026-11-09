//! Complex arithmetic and torus/integer scaling across both FFT backends.

use primus_shape::PolyLength;

use primus_decompose::DecompositionLevelCount;
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable, TfheFftTable};
use primus_lattice::GlweDimension;

#[test]
fn fourier_arithmetic_overwrites_borrowed_storage_and_matches_in_place() {
    use primus_lattice::glwe::FourierGlwe;

    let lhs = [
        Complex64::new(1.0, 2.0),
        Complex64::new(-3.0, 4.0),
        Complex64::new(5.0, -6.0),
        Complex64::new(-7.0, -8.0),
    ];
    let rhs = [Complex64::new(2.0, -1.0); 4];
    let input = FourierGlwe::new(lhs.as_slice());
    let rhs = FourierGlwe::new(rhs.as_slice());
    let mut storage = [Complex64::new(42.0, 42.0); 4];
    let mut output = FourierGlwe::new(storage.as_mut_slice());
    let view: FourierGlwe<&[Complex64]> = (&input).into();
    view.add_to(&rhs.as_view(), &mut output.as_mut_view());
    assert_eq!(output.as_ref(), &lhs.map(|x| x + Complex64::new(2.0, -1.0)));
    output.sub_assign(&rhs);
    assert_eq!(output.as_ref(), &lhs);
    input.sub_to(&rhs, &mut output);
    assert_eq!(output.as_ref(), &lhs.map(|x| x - Complex64::new(2.0, -1.0)));
    output.add_assign(&rhs);
    assert_eq!(output.as_ref(), &lhs);
    input.neg_to(&mut output);
    assert_eq!(output.as_ref(), &lhs.map(|x| -x));
    output.neg_assign();
    assert_eq!(output.as_ref(), &lhs);
    input.mul_scalar_to(-2.0, &mut output);
    assert_eq!(output.as_ref(), &lhs.map(|x| x * -2.0));
    output.mul_scalar_assign(-0.5);
    assert_eq!(output.as_ref(), &lhs);
    assert_eq!(output.into_inner().as_ptr(), storage.as_ptr());
}

// Verify the integer-multiplier/torus-ciphertext scaling contract against
// independent negacyclic convolution, with both FFT evaluation orders.
fn polynomial_products<Table: FftTable>() {
    use primus_lattice::ggsw::{FourierGgsw, Ggsw};
    use primus_poly::FourierPolynomial;
    // The minimum supported ring already exercises negacyclic wrap for this dense multiplier.
    let table = Table::new(PolyLength::new(32));
    let mut fft = FftEngine::new(&table);
    let n = fft.poly_length().get();
    let multiplier: Vec<u32> = (0..n).map(|i| (i % 5) as u32).collect();
    let mut transformed = vec![Default::default(); fft.fourier_length()];
    fft.forward_as_integer(&multiplier, &mut transformed);
    let poly = FourierPolynomial(transformed);
    // Three GGSW rows, two levels and three mask/body components.
    let components = 3 * 2 * 3;
    let input: Vec<u32> = (0..n * components).map(|i| (i * 7 % 53) as u32).collect();
    let mut expected = vec![0u32; input.len()];
    for (input, output) in input.chunks_exact(n).zip(expected.chunks_exact_mut(n)) {
        for (i, &a) in input.iter().enumerate() {
            for (j, &b) in multiplier.iter().enumerate() {
                let k = (i + j) % n;
                output[k] = if i + j < n {
                    output[k].wrapping_add(a * b)
                } else {
                    output[k].wrapping_sub(a * b)
                };
            }
        }
    }
    let coeff = Ggsw::new(input.clone());
    let mut fourier: FourierGgsw<Vec<Complex64>> =
        FourierGgsw::zero(components * fft.fourier_length());
    coeff.write_fourier_form(&mut fourier, &mut fft);
    let mut output = fourier.clone();
    fourier.mul_fourier_polynomial_to(&poly, &mut output);
    let mut recovered = Ggsw::new(vec![0; input.len()]);
    output.write_torus_form(&mut recovered, &mut fft);
    assert_eq!(recovered.as_ref(), expected);
    output.as_mut().copy_from_slice(fourier.as_ref());
    output.mul_fourier_polynomial_assign(&poly);
    output.write_torus_form(&mut recovered, &mut fft);
    assert_eq!(recovered.as_ref(), expected);
    output.as_mut().copy_from_slice(fourier.as_ref());
    output.add_mul_fourier_polynomial_assign(&fourier, &poly);
    output.write_torus_form(&mut recovered, &mut fft);
    for (x, &a) in expected.iter_mut().zip(&input) {
        *x = x.wrapping_add(a);
    }
    assert_eq!(recovered.as_ref(), expected);
}

#[test]
fn fourier_polynomial_products_preserve_torus_scale() {
    polynomial_products::<RustFftTable>();
    polynomial_products::<TfheFftTable>();
}

// The subtraction kernel absorbs a sign into the transformed monomial.
// Verify that sign and Fourier normalization with a coefficient scatter oracle.
fn sub_mul_monomial<Table: FftTable>() {
    use primus_lattice::{
        GadgetSize, GlweSize,
        ggsw::{FourierGgsw, Ggsw},
    };
    let table = Table::new(PolyLength::new(32));
    let mut fft = FftEngine::new(&table);
    let n = fft.poly_length().get();
    let size = GadgetSize::new(
        GlweSize::new(GlweDimension::new(2), PolyLength::new(n)),
        DecompositionLevelCount::new(2),
    );
    let lhs = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| (i as u32).wrapping_mul(0x9e37_79b9))
            .collect::<Vec<_>>(),
    );
    let rhs = Ggsw::new(
        (0..size.ggsw_len())
            .map(|i| (i as u32).wrapping_mul(0xa24b_aed5).wrapping_add(1))
            .collect::<Vec<_>>(),
    );
    let mut lhs_fourier = FourierGgsw::<Vec<Complex64>>::zero(size.fourier_ggsw_len());
    let mut rhs_fourier = lhs_fourier.clone();
    lhs.write_fourier_form(&mut lhs_fourier, &mut fft);
    rhs.write_fourier_form(&mut rhs_fourier, &mut fft);
    let mut output = lhs_fourier.clone();
    let mut recovered = lhs.clone();
    let mut coefficient_scratch = vec![0u32; n];
    let mut fourier_scratch = vec![Complex64::default(); fft.fourier_length()];
    // Independent signed-index oracle across every row/level/component. Zero
    // comes last to check that it subtracts rhs after dirty scratch is reused.
    for exponent in [1, n / 2, n - 1, n, n + 1, 3 * n / 2, 2 * n - 1, 0] {
        lhs_fourier.sub_mul_monomial_to(
            &rhs_fourier,
            exponent,
            &mut output,
            &mut fft,
            &mut coefficient_scratch,
            &mut fourier_scratch,
        );
        output.write_torus_form(&mut recovered, &mut fft);
        let mut expected = lhs.as_ref().to_vec();
        for (i, &value) in rhs.as_ref().iter().enumerate() {
            let position = (i % n + exponent) % (2 * n);
            let target = &mut expected[i / n * n + position % n];
            *target = if position < n {
                target.wrapping_sub(value)
            } else {
                target.wrapping_add(value)
            };
        }
        assert_eq!(recovered.as_ref(), expected, "exponent={exponent}");
    }
}

#[test]
fn fourier_gadget_sub_mul_monomial_matches_coefficient_oracle() {
    sub_mul_monomial::<RustFftTable>();
    sub_mul_monomial::<TfheFftTable>();
}
