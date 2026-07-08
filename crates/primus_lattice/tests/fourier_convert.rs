use primus_fft::{FftTable, FullComplex64FftTable};
use primus_lattice::ggsw::Ggsw;
use primus_lattice::ggsw::fourier::FourierGgswOwned;
use primus_lattice::glev::Glev;
use primus_lattice::glev::fourier::FourierGlevOwned;
use primus_lattice::glwe::Glwe;
use primus_lattice::glwe::fourier::FourierGlweOwned;

// ---------------------------------------------------------------------------
// GLWE roundtrip
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_glwe_u32() {
    for log_n in 1..=4 {
        let fft = FullComplex64FftTable::new(log_n).unwrap();
        let poly_len = fft.poly_length();
        let fourier_len = fft.fourier_length();

        let k = 2;
        let glwe_len = (k + 1) * poly_len;
        let fourier_glwe_len = (k + 1) * fourier_len;

        // Coefficient GLWE with small centered values
        let coeff: Vec<u32> = (0..glwe_len)
            .map(|i| match i % 5 {
                0 => 0u32,
                1 => 1u32,
                2 => (-1i32) as u32,
                3 => 2u32,
                _ => (-2i32) as u32,
            })
            .collect();
        let glwe = Glwe::new(coeff.clone());

        // Forward: coeff → Fourier
        let mut fourier_glwe = FourierGlweOwned::zero(fourier_glwe_len);
        glwe.write_fourier_form(&mut fourier_glwe, &fft);

        // Inverse: Fourier → coeff
        let mut result = Glwe::<Vec<u32>>::zero(glwe_len);
        fourier_glwe.write_torus_form(&mut result, &fft);

        assert_eq!(
            coeff,
            result.as_ref(),
            "GLWE u32 roundtrip failed for log_n={log_n}"
        );
    }
}

#[test]
fn roundtrip_glwe_u64() {
    for log_n in 1..=3 {
        let fft = FullComplex64FftTable::new(log_n).unwrap();
        let poly_len = fft.poly_length();
        let fourier_len = fft.fourier_length();

        let k = 1;
        let glwe_len = (k + 1) * poly_len;
        let fourier_glwe_len = (k + 1) * fourier_len;

        let coeff: Vec<u64> = (0..glwe_len)
            .map(|i| match i % 5 {
                0 => 0u64,
                1 => 1u64,
                2 => (-1i64) as u64,
                3 => 2u64,
                _ => (-2i64) as u64,
            })
            .collect();
        let glwe = Glwe::new(coeff.clone());

        let mut fourier_glwe = FourierGlweOwned::zero(fourier_glwe_len);
        glwe.write_fourier_form(&mut fourier_glwe, &fft);

        let mut result = Glwe::<Vec<u64>>::zero(glwe_len);
        fourier_glwe.write_torus_form(&mut result, &fft);

        assert_eq!(
            coeff,
            result.as_ref(),
            "GLWE u64 roundtrip failed for log_n={log_n}"
        );
    }
}

// ---------------------------------------------------------------------------
// GLEV roundtrip
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_glev_u32() {
    let log_n = 3;
    let fft = FullComplex64FftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    let k = 1;
    let level = 2;
    let glwe_len = (k + 1) * poly_len; // 2 * 8 = 16
    let glev_len = level * glwe_len; // 2 * 16 = 32
    let fourier_glwe_len = (k + 1) * fourier_len;
    let fourier_glev_len = level * fourier_glwe_len;

    let coeff: Vec<u32> = (0..glev_len)
        .map(|i| match i % 5 {
            0 => 0u32,
            1 => 1u32,
            2 => (-1i32) as u32,
            3 => 2u32,
            _ => (-2i32) as u32,
        })
        .collect();
    let glev = Glev::new(coeff.clone());

    let mut fourier_glev = FourierGlevOwned::zero(fourier_glev_len);
    glev.write_fourier_form(&mut fourier_glev, &fft);

    let mut result = Glev::<Vec<u32>>::zero(glev_len);
    fourier_glev.write_torus_form(&mut result, &fft);

    assert_eq!(coeff, result.as_ref(), "GLEV u32 roundtrip failed");
}

// ---------------------------------------------------------------------------
// GGSW roundtrip
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_ggsw_u32() {
    let log_n = 2;
    let fft = FullComplex64FftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    let k = 1;
    let level = 1;
    let glwe_len = (k + 1) * poly_len; // 2 * 4 = 8
    let glev_len = level * glwe_len; // 1 * 8 = 8
    let ggsw_len = (k + 1) * glev_len; // 2 * 8 = 16
    let fourier_glwe_len = (k + 1) * fourier_len;
    let fourier_glev_len = level * fourier_glwe_len;
    let fourier_ggsw_len = (k + 1) * fourier_glev_len;

    let coeff: Vec<u32> = (0..ggsw_len)
        .map(|i| match i % 5 {
            0 => 0u32,
            1 => 1u32,
            2 => (-1i32) as u32,
            3 => 2u32,
            _ => (-2i32) as u32,
        })
        .collect();
    let ggsw = Ggsw::new(coeff.clone());

    let mut fourier_ggsw = FourierGgswOwned::zero(fourier_ggsw_len);
    ggsw.write_fourier_form(&mut fourier_ggsw, &fft);

    let mut result = Ggsw::<Vec<u32>>::zero(ggsw_len);
    fourier_ggsw.write_torus_form(&mut result, &fft);

    assert_eq!(coeff, result.as_ref(), "GGSW u32 roundtrip failed");
}

// ---------------------------------------------------------------------------
// Shape boundary tests
// ---------------------------------------------------------------------------

#[test]
fn glwe_shape_matches_fourier_shape() {
    let log_n = 3;
    let fft = FullComplex64FftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    for k in 1..=3 {
        let glwe_len = (k + 1) * poly_len;
        let fourier_glwe_len = (k + 1) * fourier_len;

        let glwe = Glwe::<Vec<u32>>::zero(glwe_len);
        let mut fourier = FourierGlweOwned::zero(fourier_glwe_len);
        glwe.write_fourier_form(&mut fourier, &fft);

        assert_eq!(fourier.byte_count(), fourier_glwe_len * 16);
    }
}

#[test]
fn zero_glwe_roundtrip() {
    let log_n = 3;
    let fft = FullComplex64FftTable::new(log_n).unwrap();
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();

    let k = 2;
    let glwe_len = (k + 1) * poly_len;
    let fourier_glwe_len = (k + 1) * fourier_len;

    let glwe = Glwe::<Vec<u32>>::zero(glwe_len);
    let mut fourier = FourierGlweOwned::zero(fourier_glwe_len);
    glwe.write_fourier_form(&mut fourier, &fft);

    // After forward transform, Fourier should still be close to zero
    // (all-zero input → all-zero Fourier output)
    for &c in fourier.as_ref() {
        assert!(
            c.re.abs() < 1e-12 && c.im.abs() < 1e-12,
            "zero input should produce zero Fourier output"
        );
    }

    let mut result = Glwe::<Vec<u32>>::zero(glwe_len);
    fourier.write_torus_form(&mut result, &fft);
    for &v in result.as_ref() {
        assert_eq!(v, 0u32, "zero roundtrip should be exact");
    }
}
