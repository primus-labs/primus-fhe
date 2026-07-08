use num_complex::Complex64;
use primus_lattice::ggsw::fourier::{FourierGgsw, FourierGgswIter, FourierGgswOwned};
use primus_lattice::glev::fourier::{FourierGlev, FourierGlevIter, FourierGlevOwned};
use primus_lattice::glwe::fourier::{FourierGlwe, FourierGlweIter, FourierGlweOwned};

// ---------------------------------------------------------------------------
// FourierGlwe tests
// ---------------------------------------------------------------------------

#[test]
fn fourier_glwe_new_and_zero() {
    let glwe = FourierGlweOwned::zero(6);
    assert_eq!(glwe.byte_count(), 6 * 16);
}

#[test]
fn fourier_glwe_set_zero() {
    let data = vec![Complex64::new(1.0, 2.0); 12];
    let mut glwe = FourierGlwe::new(data);
    glwe.set_zero();
    assert!(glwe.as_ref().iter().all(|&x| x == Complex64::new(0.0, 0.0)));
}

#[test]
fn fourier_glwe_a_b_slices() {
    let flen = 3;
    let k = 2;
    let glwe_len = (k + 1) * flen;
    let mid = k * flen;
    let data = vec![Complex64::new(0.0, 0.0); glwe_len];
    let glwe = FourierGlwe::new(data);
    let (a, b) = glwe.a_b_slices(mid);
    assert_eq!(a.len(), mid);
    assert_eq!(b.len(), flen);
}

#[test]
fn fourier_glwe_a_b_mut_slices() {
    let flen = 2;
    let k = 1;
    let glwe_len = (k + 1) * flen;
    let mid = k * flen;
    let mut glwe = FourierGlweOwned::zero(glwe_len);
    {
        let (a, b) = glwe.a_b_mut_slices(mid);
        a[0] = Complex64::new(1.0, 0.0);
        b[0] = Complex64::new(2.0, 0.0);
    }
    assert_eq!(glwe.as_ref()[0], Complex64::new(1.0, 0.0));
    assert_eq!(glwe.as_ref()[mid], Complex64::new(2.0, 0.0));
}

#[test]
fn fourier_glwe_iter_fourier_poly() {
    let data = vec![Complex64::new(1.0, 0.0); 4];
    let glwe = FourierGlwe::new(data);
    let polys: Vec<_> = glwe.iter_fourier_poly(2).collect();
    assert_eq!(polys.len(), 2);
    assert_eq!(polys[0].fourier_length(), 2);
    assert_eq!(polys[1].fourier_length(), 2);
}

#[test]
fn fourier_glwe_iterator() {
    let glwe_len = 4;
    let data = vec![Complex64::new(0.0, 0.0); 8];
    let iter = FourierGlweIter::new(&data, glwe_len);
    assert_eq!(iter.count(), 2);
}

// ---------------------------------------------------------------------------
// FourierGlev tests
// ---------------------------------------------------------------------------

#[test]
fn fourier_glev_new_and_zero() {
    let glev = FourierGlevOwned::zero(36);
    assert_eq!(glev.byte_count(), 36 * 16);
}

#[test]
fn fourier_glev_set_zero() {
    let data = vec![Complex64::new(1.0, 2.0); 18];
    let mut glev = FourierGlev::new(data);
    glev.set_zero();
    assert!(glev.as_ref().iter().all(|&x| x == Complex64::new(0.0, 0.0)));
}

#[test]
fn fourier_glev_iter_glwe() {
    let glwe_len = 4;
    let glev_len = 12;
    let data = vec![Complex64::new(0.0, 0.0); glev_len];
    let glev = FourierGlev::new(data);
    let glwes: Vec<_> = glev.iter_glwe(glwe_len).collect();
    assert_eq!(glwes.len(), 3);
}

#[test]
fn fourier_glev_iterator() {
    let glev_len = 12;
    let data = vec![Complex64::new(0.0, 0.0); 24];
    let iter = FourierGlevIter::new(&data, glev_len);
    assert_eq!(iter.count(), 2);
}

// ---------------------------------------------------------------------------
// FourierGgsw tests
// ---------------------------------------------------------------------------

#[test]
fn fourier_ggsw_new_and_zero() {
    let ggsw = FourierGgswOwned::zero(72);
    assert_eq!(ggsw.byte_count(), 72 * 16);
}

#[test]
fn fourier_ggsw_set_zero() {
    let data = vec![Complex64::new(1.0, 2.0); 72];
    let mut ggsw = FourierGgsw::new(data);
    ggsw.set_zero();
    assert!(ggsw.as_ref().iter().all(|&x| x == Complex64::new(0.0, 0.0)));
}

#[test]
fn fourier_ggsw_iter_glev() {
    let glev_len = 8;
    let ggsw_len = 16;
    let data = vec![Complex64::new(0.0, 0.0); ggsw_len];
    let ggsw = FourierGgsw::new(data);
    let glevs: Vec<_> = ggsw.iter_glev(glev_len).collect();
    assert_eq!(glevs.len(), 2);
}

#[test]
fn fourier_ggsw_iterator() {
    let ggsw_len = 16;
    let data = vec![Complex64::new(0.0, 0.0); 32];
    let iter = FourierGgswIter::new(&data, ggsw_len);
    assert_eq!(iter.count(), 2);
}
