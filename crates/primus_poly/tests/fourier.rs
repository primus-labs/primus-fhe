//! Pointwise arithmetic has no transform normalization. Small deterministic
//! fixtures cover arithmetic, fused rounding, and borrowed output boundaries.

use num_complex::Complex64;
use primus_poly::FourierPolynomial;

#[test]
fn pointwise_arithmetic_matches_complex_oracle() {
    let lhs = FourierPolynomial::new([Complex64::new(1.0, 2.0), Complex64::new(-3.0, 1.0)]);
    let rhs = FourierPolynomial::new([Complex64::new(2.0, -1.0), Complex64::new(0.5, 2.0)]);
    let sum = [Complex64::new(3.0, 1.0), Complex64::new(-2.5, 3.0)];
    let difference = [Complex64::new(-1.0, 3.0), Complex64::new(-3.5, -1.0)];
    let product = [Complex64::new(4.0, 3.0), Complex64::new(-3.5, -5.5)];
    let scaled = [Complex64::new(-2.5, -5.0), Complex64::new(7.5, -2.5)];
    let negative = [Complex64::new(-1.0, -2.0), Complex64::new(3.0, -1.0)];

    // Assign and out-of-place kernels have separate write/aliasing contracts;
    // consuming wrappers that just call assign need no duplicate checks.
    let mut inplace = lhs.clone();
    inplace.as_mut_view().add_assign(&rhs.as_view());
    assert_eq!(inplace.as_slice(), sum);
    inplace.copy_from(&lhs);
    inplace.as_mut_view().sub_assign(&rhs);
    assert_eq!(inplace.as_slice(), difference);
    inplace.copy_from(&lhs);
    inplace.mul_assign(&rhs);
    assert_eq!(inplace.as_slice(), product);

    // A nonzero accumulator distinguishes += lhs*rhs from an overwrite.
    inplace.copy_from(&lhs);
    inplace.add_mul_assign(&lhs.as_view(), &rhs.as_view());
    assert_eq!(
        inplace.as_slice(),
        [Complex64::new(5.0, 5.0), Complex64::new(-6.5, -4.5)]
    );
    inplace.copy_from(&lhs);
    inplace.mul_scalar_assign(-2.5);
    assert_eq!(inplace.as_slice(), scaled);
    inplace.copy_from(&lhs);
    inplace.neg_assign();
    assert_eq!(inplace.as_slice(), negative);

    let mut output = lhs.clone();
    // Mutable views write the owner's storage; shared views retain the representation.
    let rhs_view: FourierPolynomial<&[Complex64]> = (&rhs).into();
    lhs.as_view().add_to(&rhs_view, &mut output.as_mut_view());
    assert_eq!(output.as_slice(), sum);
    lhs.sub_to(&rhs_view, &mut output.as_mut_view());
    assert_eq!(output.as_slice(), difference);
    lhs.sub_rev_assign(&mut output);
    assert_eq!(output, rhs);
    lhs.as_view().mul_to(&rhs, &mut output.as_mut_view());
    assert_eq!(output.as_slice(), product);
    lhs.mul_scalar_to(-2.5, &mut output);
    assert_eq!(output.as_slice(), scaled);
    lhs.neg_to(&mut output);
    assert_eq!(output.as_slice(), negative);
}

#[test]
fn fused_multiply_add_preserves_rounding_and_slice_boundaries() {
    #[repr(C, align(64))]
    struct FmaBuffer {
        aligned: [Complex64; 16],
        padding: f64,
        shifted: [Complex64; 16],
    }

    impl FmaBuffer {
        fn new(guard: Complex64) -> Self {
            Self {
                aligned: [guard; 16],
                padding: 0.0,
                shifted: [guard; 16],
            }
        }

        fn values(&mut self, skew: usize) -> &mut [Complex64] {
            if skew == 0 {
                &mut self.aligned
            } else {
                &mut self.shifted
            }
        }
    }

    let c = Complex64::new;
    let eps = f64::EPSILON;
    let tiny = f64::from_bits(1);
    // (1+eps)*(1-eps) = 1-eps² exactly. A separately rounded product
    // loses eps²; these four cases distinguish both inner and outer FMAs.
    let a = 1.0 + eps;
    let b = 1.0 - eps;
    let residual = eps * eps;
    // Each tuple is (lhs, rhs, initial accumulator, expected result).
    let cases = [
        (c(a, 0.0), c(b, 0.0), c(-1.0, 0.0), c(-residual, 0.0)),
        (c(a, 0.0), c(0.0, b), c(0.0, -1.0), c(0.0, -residual)),
        (c(0.0, a), c(0.0, b), c(1.0, 0.0), c(residual, 0.0)),
        (c(0.0, a), c(b, 0.0), c(0.0, -1.0), c(0.0, -residual)),
        // The exact 1.5*tiny rounds to the even subnormal 2*tiny.
        (
            c(tiny, 0.0),
            c(0.5, 0.0),
            c(tiny, -tiny),
            c(2.0 * tiny, -tiny),
        ),
        (c(0.0, 0.0), c(-0.0, 0.0), c(0.0, -0.0), c(-0.0, 0.0)),
        // Intermediate overflow follows the fused order, not inf - inf.
        (
            c(f64::MAX, f64::MAX),
            c(2.0, 2.0),
            c(0.0, 0.0),
            c(f64::NEG_INFINITY, f64::INFINITY),
        ),
        (
            c(f64::NAN, 1.0),
            c(1.0, 2.0),
            c(3.0, 4.0),
            c(f64::NAN, f64::NAN),
        ),
    ];
    let guard = c(99.0, -99.0);
    // Rotate the fixtures so each value appears in SIMD lanes and scalar tails.
    // Each aligned array occupies a multiple of 64 bytes. The f64 field shifts the
    // second array by 8 bytes; stepping by one complex reaches every 8-byte
    // address class modulo 64 for each operand.
    for address in (0..64).step_by(8) {
        let offset = address / 16;
        let skew = address % 16;
        for shift in 0..cases.len() {
            for len in [0, 1, 3, 4, 5, 8, 9] {
                let lhs_offset = (offset + 1) & 3;
                let rhs_offset = (offset + 2) & 3;
                let mut lhs_buffer = FmaBuffer::new(guard);
                let mut rhs_buffer = FmaBuffer::new(guard);
                let mut output_buffer = FmaBuffer::new(guard);
                let lhs = lhs_buffer.values(skew);
                let rhs = rhs_buffer.values(skew);
                let output = output_buffer.values(skew);
                for i in 0..len {
                    let (a, b, acc, _) = cases[(shift + i) % cases.len()];
                    lhs[lhs_offset + i] = a;
                    rhs[rhs_offset + i] = b;
                    output[offset + i] = acc;
                }
                let lhs = &lhs[lhs_offset..lhs_offset + len];
                let rhs = &rhs[rhs_offset..rhs_offset + len];
                let acc = &mut output[offset..offset + len];
                assert_eq!(
                    [lhs.as_ptr(), rhs.as_ptr(), acc.as_ptr()].map(|ptr| ptr.addr() % 64),
                    [16 * lhs_offset + skew, 16 * rhs_offset + skew, address]
                );
                FourierPolynomial(acc)
                    .add_mul_assign(&FourierPolynomial(lhs), &FourierPolynomial(rhs));
                for i in 0..len {
                    let actual = output[offset + i];
                    let expected = cases[(shift + i) % cases.len()].3;
                    for (actual, expected) in [(actual.re, expected.re), (actual.im, expected.im)] {
                        if expected.is_nan() {
                            assert!(actual.is_nan());
                        } else {
                            assert_eq!(
                                actual.to_bits(),
                                expected.to_bits(),
                                "case={}, len={len}, output address modulo 64={address}",
                                (shift + i) % cases.len()
                            );
                        }
                    }
                }
                assert!(
                    output[..offset]
                        .iter()
                        .chain(&output[offset + len..])
                        .all(|&x| x == guard)
                );
            }
        }
    }
}
