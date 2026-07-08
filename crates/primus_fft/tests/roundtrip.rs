use num_complex::Complex64;
use primus_fft::{FullComplex64FftTable, FftTable};

/// Small centered coefficients should roundtrip exactly through
/// forward + inverse transform for all N from 2 to 64.
#[test]
fn roundtrip_u32_small() {
    for log_n in 1..=6 {
        let table = FullComplex64FftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let flen = table.fourier_length();

        let mut fourier = vec![Complex64::new(0.0, 0.0); flen];
        let mut output = vec![0u32; n];

        // Test pattern: small centered values [-2, -1, 0, 1, 2] (wrapped to u32)
        let input: Vec<u32> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                _ => (-2i32) as u32,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_u32_small failed for log_n={log_n}"
        );
    }
}

/// A single non-zero coefficient (monomial) should roundtrip exactly.
#[test]
fn roundtrip_u32_monomial() {
    for log_n in 1..=6 {
        let table = FullComplex64FftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let flen = table.fourier_length();

        let mut fourier = vec![Complex64::new(0.0, 0.0); flen];
        let mut output = vec![0u32; n];

        for pos in [0, 1, n / 2, n - 1] {
            let mut input = vec![0u32; n];
            input[pos] = 1;

            fourier.fill(Complex64::new(0.0, 0.0));
            output.fill(0);

            table.forward_torus_slice(&input, &mut fourier);
            table.inverse_torus_slice(&fourier, &mut output);
            assert_eq!(
                input, output,
                "roundtrip_u32_monomial failed for log_n={log_n}, pos={pos}"
            );
        }
    }
}

/// All-zeros polynomial roundtrips exactly.
#[test]
fn roundtrip_zero_polynomial() {
    for log_n in 1..=6 {
        let table = FullComplex64FftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let flen = table.fourier_length();

        let input = vec![0u32; n];
        let mut fourier = vec![Complex64::new(0.0, 0.0); flen];
        let mut output = vec![1u32; n]; // start with non-zero to catch failures

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_zero_polynomial failed for log_n={log_n}"
        );
    }
}

/// Constant-1 polynomial roundtrips exactly (identity element).
#[test]
fn roundtrip_one_polynomial() {
    for log_n in 1..=6 {
        let table = FullComplex64FftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let flen = table.fourier_length();

        let mut input = vec![0u32; n];
        input[0] = 1;

        let mut fourier = vec![Complex64::new(0.0, 0.0); flen];
        let mut output = vec![0u32; n];

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_one_polynomial failed for log_n={log_n}"
        );
    }
}

/// u64 roundtrip for small values (within f64 exact integer range, |v| <= 2^53).
#[test]
fn roundtrip_u64_small() {
    for log_n in 1..=4 {
        let table = FullComplex64FftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let flen = table.fourier_length();

        let mut fourier = vec![Complex64::new(0.0, 0.0); flen];
        let mut output = vec![0u64; n];

        // Small values that fit exactly in f64 (53-bit mantissa)
        let input: Vec<u64> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u64,
                1 => 1u64,
                2 => (-1i64) as u64,
                3 => 2u64,
                _ => (-2i64) as u64,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_u64_small failed for log_n={log_n}"
        );
    }
}

/// u16 roundtrip for small values.
#[test]
fn roundtrip_u16_small() {
    for log_n in 1..=4 {
        let table = FullComplex64FftTable::new(log_n).unwrap();
        let n = table.poly_length();
        let flen = table.fourier_length();

        let mut fourier = vec![Complex64::new(0.0, 0.0); flen];
        let mut output = vec![0u16; n];

        let input: Vec<u16> = (0..n)
            .map(|i| match i % 5 {
                0 => 0u16,
                1 => 1u16,
                2 => (-1i16) as u16,
                3 => 2u16,
                _ => (-2i16) as u16,
            })
            .collect();

        table.forward_torus_slice(&input, &mut fourier);
        table.inverse_torus_slice(&fourier, &mut output);
        assert_eq!(
            input, output,
            "roundtrip_u16_small failed for log_n={log_n}"
        );
    }
}
