//! Body-only updates and gadget diagonals, with independent flat-layout oracles.
//! Coefficient/NTT wrappers share these macros, as do CRT/DCRT wrappers; one
//! representative per macro suffices. Fourier has its own complex arithmetic.

use primus_decompose::DecompositionLevelCount;
use primus_lattice::GlweDimension;
use primus_lattice::{GadgetSize, GlweSize, ggsw::Ggsw, glwe::Glwe, lwe::Lwe};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;

#[test]
fn encoded_plaintext_operations_preserve_masks_and_trivial_overwrites_them() {
    // These are layout checks, not transform tests: a four-coefficient body
    // distinguishes mask/body boundaries without a vector-sized ring.
    const N: usize = 4;
    const Q: u32 = 193;
    let modulus = BarrettModulus::new(Q);
    let plaintext = Polynomial::new([0, 1, 96, 192]);
    let data: Vec<u32> = (0..N * 3).map(|i| (i * 37 % Q as usize) as u32).collect();
    let mut cipher = Glwe::new(data.clone());
    cipher.add_plaintext_assign(&plaintext, modulus);
    assert_eq!(&cipher.as_ref()[..2 * N], &data[..2 * N]);
    for (i, &value) in plaintext.as_ref().iter().enumerate() {
        assert_eq!(cipher.as_ref()[2 * N + i], (data[2 * N + i] + value) % Q);
    }
    cipher.sub_plaintext_assign(&plaintext, modulus);
    assert_eq!(cipher.as_ref(), data);
    cipher.set_trivial(&plaintext);
    assert_eq!(&cipher.as_ref()[..2 * N], &[0; 2 * N]);
    assert_eq!(&cipher.as_ref()[2 * N..], plaintext.as_ref());

    // LWE uses a scalar body and has a separate implementation.
    let mut lwe = Lwe::new(vec![11u32, 13, 190]);
    lwe.add_plaintext_assign(7, modulus);
    assert_eq!(lwe.as_ref(), &[11, 13, 4]);
    lwe.sub_plaintext_assign(7, modulus);
    assert_eq!(lwe.as_ref(), &[11, 13, 190]);
    lwe.set_trivial(7);
    assert_eq!(lwe.as_ref(), &[0, 0, 7]);
}

// Decode every flat index independently of the implementation's diagonal
// iterator. Off-diagonal entries and unselected levels must remain unchanged.
fn diagonal_oracle(
    data: &[u32],
    plaintext: &[u32],
    rows: usize,
    levels: usize,
    selected: usize,
    n: usize,
    qs: &[u32],
) -> Vec<u32> {
    let p = plaintext.len();
    data.iter()
        .enumerate()
        .map(|(i, &value)| {
            let row = i / (levels * rows * p);
            let level = i / (rows * p) % levels;
            let component = i / p % rows;
            if row == component && level == selected {
                (value + plaintext[i % p]) % qs[i % p / n]
            } else {
                value
            }
        })
        .collect()
}

#[test]
fn gadget_injection_changes_only_the_selected_diagonal_level() {
    const N: usize = 32;
    const LEVELS: usize = 3;
    let modulus = BarrettModulus::new(193u32);
    let plaintext = Polynomial::new([0, 1, 96, 192].repeat(N / 4));
    let size = GadgetSize::new(
        GlweSize::new(GlweDimension::new(2), PolyLength::new(N)),
        DecompositionLevelCount::new(LEVELS),
    );
    let data: Vec<_> = (0..size.ggsw_len()).map(|i| (i * 7 % 193) as u32).collect();
    let mut cipher = Ggsw::new(data.clone());
    // First, interior and last levels expose wrong row/level strides.
    for selected in 0..LEVELS {
        cipher.as_mut().copy_from_slice(&data);
        cipher.add_gadget_diagonal_assign(&plaintext, selected, size, modulus);
        assert_eq!(
            cipher.as_ref(),
            diagonal_oracle(&data, plaintext.as_ref(), 3, LEVELS, selected, N, &[193]),
            "level={selected}"
        );
    }
}

#[cfg(feature = "rns")]
#[test]
fn rns_plaintext_and_gadget_operations_preserve_the_basis_layout() {
    use primus_lattice::{RnsGadgetSize, RnsGlweSize, ggsw::DcrtGgsw, glwe::CrtGlwe};
    use primus_poly::{CrtPolynomial, DcrtPolynomial};

    const N: usize = 32;
    const LEVELS: usize = 3;
    let qs = [193u32, 257];
    let moduli = qs.map(BarrettModulus::new);
    let p = N * qs.len();
    let plaintext: Vec<u32> = (0..p).map(|i| (i * 53) as u32 % qs[i / N]).collect();
    let size = RnsGadgetSize::new(
        RnsGlweSize::new(
            GlweSize::new(GlweDimension::new(2), PolyLength::new(N)),
            qs.len(),
        ),
        DecompositionLevelCount::new(LEVELS),
    );

    // CRT body and DCRT gadget each instantiate one shared RNS macro. Distinct
    // residues expose swapping a modulus block with a ciphertext component.
    let data: Vec<_> = (0..p * 3)
        .map(|i| (i * 37) as u32 % qs[i / N % 2])
        .collect();
    let mut cipher = CrtGlwe::new(data.clone());
    let poly = CrtPolynomial::new(plaintext.as_slice());
    cipher.add_plaintext_assign(&poly, N, &moduli);
    assert_eq!(&cipher.as_ref()[..2 * p], &data[..2 * p]);
    for (i, &value) in plaintext.iter().enumerate() {
        assert_eq!(
            cipher.as_ref()[2 * p + i],
            (data[2 * p + i] + value) % qs[i / N]
        );
    }
    cipher.sub_plaintext_assign(&poly, N, &moduli);
    assert_eq!(cipher.as_ref(), data);
    cipher.set_trivial(&poly);
    assert!(cipher.as_ref()[..2 * p].iter().all(|&x| x == 0));
    assert_eq!(&cipher.as_ref()[2 * p..], plaintext);

    let data: Vec<_> = (0..size.rns_ggsw_len())
        .map(|i| (i * 7) as u32 % qs[i / N % 2])
        .collect();
    let mut cipher = DcrtGgsw::new(data.clone());
    let poly = DcrtPolynomial::new(plaintext.as_slice());
    for selected in 0..LEVELS {
        cipher.as_mut().copy_from_slice(&data);
        cipher.add_gadget_diagonal_assign(&poly, selected, size, &moduli);
        assert_eq!(
            cipher.as_ref(),
            diagonal_oracle(&data, &plaintext, 3, LEVELS, selected, N, &qs),
            "level={selected}"
        );
    }
}

#[cfg(feature = "fourier")]
#[test]
fn fourier_body_and_gadget_operations_preserve_complex_entries() {
    use primus_fft::Complex64;
    use primus_lattice::{ggsw::FourierGgsw, glwe::FourierGlwe};
    use primus_poly::FourierPolynomial;

    // N counts complex entries here; the corresponding ring has 2*N coefficients.
    const N: usize = 16;
    let plaintext: Vec<_> = (0..N)
        .map(|i| Complex64::new(i as f64, -(i as f64)))
        .collect();
    let poly = FourierPolynomial::new(plaintext.as_slice());
    let data: Vec<_> = (0..3 * N)
        .map(|i| Complex64::new((i * 3) as f64, 7.0))
        .collect();
    let mut glwe = FourierGlwe::new(data.clone());
    glwe.add_plaintext_assign(&poly);
    assert_eq!(&glwe.as_ref()[..2 * N], &data[..2 * N]);
    for (i, &p) in plaintext.iter().enumerate() {
        assert_eq!(glwe.as_ref()[2 * N + i], data[2 * N + i] + p);
    }
    glwe.sub_plaintext_assign(&poly);
    assert_eq!(glwe.as_ref(), data);
    glwe.set_trivial(&poly);
    assert!(
        glwe.as_ref()[..2 * N]
            .iter()
            .all(|&x| x == Complex64::default())
    );
    assert_eq!(&glwe.as_ref()[2 * N..], plaintext);

    let data: Vec<_> = (0..3 * 2 * 3 * N)
        .map(|i| Complex64::new((i * 3) as f64, 7.0))
        .collect();
    let mut ggsw = FourierGgsw::new(data.clone());
    ggsw.add_gadget_diagonal_assign(
        &poly,
        1,
        GadgetSize::new(
            GlweSize::new(GlweDimension::new(2), PolyLength::new(2 * N)),
            DecompositionLevelCount::new(2),
        ),
    );
    for (i, &value) in data.iter().enumerate() {
        let row = i / (2 * 3 * N);
        let level = i / (3 * N) % 2;
        let component = i / N % 3;
        let expected = if level == 1 && component == row {
            value + plaintext[i % N]
        } else {
            value
        };
        assert_eq!(ggsw.as_ref()[i], expected);
    }
}
