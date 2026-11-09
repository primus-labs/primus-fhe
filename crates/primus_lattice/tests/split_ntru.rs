//! Native wrap/limb/carry boundaries against an independent integer convolution.
#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_fft::{Complex64, FftEngine, FftTable};
use primus_lattice::{
    ntru::FourierNtruSplitGadget,
    workspace::{FourierNtruExternalProductWorkspace, FourierNtruSplitWorkspace},
};
use primus_poly::FourierPolynomial;
use primus_shape::PolyLength;

// Independent limb construction for one selected row. The inverse roundings
// stay separate: a one-unit high-limb error becomes 2^bits after recombination.
// At extreme splits this reference checks the representation/rounding order,
// not an unsupported claim that floating-point convolution is always exact.
fn split_row_reference<Table: FftTable>(
    row: &[u64],
    digits: &[u64],
    bits: u32,
    fft: &mut FftEngine<'_, Table>,
) -> Vec<u64> {
    let half_n = row.len() / 2;
    let mask = (1u64 << bits) - 1;
    let mut digit_fft = vec![Complex64::default(); half_n];
    fft.forward_as_integer(digits, &mut digit_fft);
    let mut rounded = Vec::new();
    for limb in [
        row.iter().map(|&value| value & mask).collect::<Vec<_>>(),
        row.iter().map(|&value| value >> bits).collect(),
    ] {
        let mut spectrum = vec![Complex64::default(); half_n];
        let mut accumulator = vec![Complex64::default(); half_n];
        let mut output = vec![0u64; row.len()];
        fft.forward_as_torus(&limb, &mut spectrum);
        FourierPolynomial(&mut accumulator).add_mul_assign(
            &FourierPolynomial(&digit_fft),
            &FourierPolynomial(&spectrum),
        );
        fft.backward_as_torus(&accumulator, &mut output);
        rounded.push(output);
    }
    rounded[0]
        .iter()
        .zip(&rounded[1])
        .map(|(&low, &high)| low.wrapping_add(high << bits))
        .collect()
}

fn reusable_material<Table: FftTable>() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let n = PolyLength::new(32);
    let table = Table::new(n);
    let other_table = Table::new(PolyLength::new(64));
    let mut fft = FftEngine::new(&table);
    let mut other_fft = FftEngine::new(&other_table);
    let basis = ApproxSignedBasis::<u64>::try_from((
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(16)),
        },
        None,
    ))
    .unwrap();
    let mut ordinary = FourierNtruExternalProductWorkspace::new(n);
    let mut wrong_workspace = FourierNtruExternalProductWorkspace::new(PolyLength::new(64));
    let mut split = FourierNtruSplitWorkspace::new(n);
    let digits: Vec<_> = (0..n.get())
        .map(|index| u64::from(index == 0 || index == n.get() - 1))
        .collect();
    let mut output = vec![u64::MAX; n.get()];
    for bits in [1, 35, 40, 63] {
        let mut key = FourierNtruSplitGadget::zero(n, &basis, bits);
        key.external_product_to(&digits, &mut output, &mut fft, &mut ordinary, &mut split);
        assert_eq!(output, vec![0; n.get()]);

        // Refill after previous external products have dirtied every scratch
        // buffer. Low/high carry boundaries and native wrapping are explicit.
        let mask = (1u64 << bits) - 1;
        let values = [0, 1, mask, mask + 1, u64::MAX, 1u64 << 63];
        for offset in [0, 3] {
            let rows: Vec<_> = (0..n.get() * 16)
                .map(|index| values[(index / 3 + index / n.get() + offset) % values.len()])
                .collect();
            key.set_from_coefficients(&rows, &mut fft, &mut ordinary);
            let constructed =
                FourierNtruSplitGadget::from_coefficients(&rows, &basis, bits, &mut fft);
            for level in [0, 7, 15] {
                let scalar = basis.scalar_iter().nth(level).unwrap();
                let input: Vec<_> = digits.iter().map(|&digit| digit * scalar).collect();
                key.external_product_to(&input, &mut output, &mut fft, &mut ordinary, &mut split);
                let expected = split_row_reference(
                    &rows[level * n.get()..(level + 1) * n.get()],
                    &digits,
                    bits,
                    &mut fft,
                );
                assert_eq!(output, expected);
                let mut from_output = vec![0; n.get()];
                constructed.external_product_to(
                    &input,
                    &mut from_output,
                    &mut fft,
                    &mut ordinary,
                    &mut split,
                );
                assert_eq!(from_output, expected);
            }

            // All public shape failures precede spectrum writes. A later valid
            // product must still consume the complete previous material.
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    key.set_from_coefficients(&rows[..rows.len() - 1], &mut fft, &mut ordinary);
                }))
                .is_err()
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    key.set_from_coefficients(&rows, &mut other_fft, &mut ordinary);
                }))
                .is_err()
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    key.set_from_coefficients(&rows, &mut fft, &mut wrong_workspace);
                }))
                .is_err()
            );
            key.external_product_to(&digits, &mut output, &mut fft, &mut ordinary, &mut split);
            assert_eq!(
                output,
                split_row_reference(&rows[..n.get()], &digits, bits, &mut fft)
            );
        }

        // Small exact coefficients stay far inside the limb precision budget;
        // this checks the real negacyclic product independently of the FFTs.
        let rows: Vec<_> = (0..n.get() * 16)
            .map(|index| (index % 101) as u64)
            .collect();
        key.set_from_coefficients(&rows, &mut fft, &mut ordinary);
        key.external_product_to(&digits, &mut output, &mut fft, &mut ordinary, &mut split);
        assert_eq!(output, product(&rows[..n.get()], &digits));
    }
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_reusable_material() {
    reusable_material::<primus_fft::RustFftTable>();
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_reusable_material() {
    reusable_material::<primus_fft::TfheFftTable>();
}

#[test]
fn split_zero_rejects_unsupported_representation() {
    let n = PolyLength::new(32);
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: Some(DecompositionLevelCount::new(4)),
    };
    let native = ApproxSignedBasis::<u64>::try_from((config, None)).unwrap();
    let non_native = ApproxSignedBasis::<u64>::try_from((config, Some(1 << 40))).unwrap();
    let narrow = ApproxSignedBasis::<u32>::try_from((config, None)).unwrap();
    for bits in [0, 64] {
        assert!(
            std::panic::catch_unwind(|| FourierNtruSplitGadget::zero(n, &native, bits)).is_err()
        );
    }
    assert!(std::panic::catch_unwind(|| FourierNtruSplitGadget::zero(n, &non_native, 35)).is_err());
    assert!(std::panic::catch_unwind(|| FourierNtruSplitGadget::zero(n, &narrow, 16)).is_err());
}

fn boundaries<Table: FftTable>() {
    let n = PolyLength::new(32);
    let table = Table::new(n);
    let mut fft = FftEngine::new(&table);
    let basis = ApproxSignedBasis::<u64>::try_from((
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(16)),
        },
        None,
    ))
    .unwrap();
    let input: Vec<_> = (0..n.get())
        .map(|i| match i & 3 {
            0 => 0,
            1 => 8,
            2 => u64::MAX,
            _ => 1u64 << 63,
        })
        .collect();
    let mut ordinary = FourierNtruExternalProductWorkspace::new(n);
    let mut split = FourierNtruSplitWorkspace::new(n);
    for bits in [35, 40] {
        let values = [0, (1u64 << bits) - 1, 1u64 << bits, u64::MAX];
        let rows: Vec<_> = (0..n.get() * 16)
            .map(|i| values[(i / 3 + i / 32) & 3])
            .collect();
        let key = FourierNtruSplitGadget::from_coefficients(&rows, &basis, bits, &mut fft);
        let mut expected = vec![0u64; n.get()];
        let mut carries = vec![false; n.get()];
        let mut digits = vec![0u64; n.get()];
        basis.init_carry_slice(&input, &mut carries);
        for (decomposer, row) in basis.decomposer_iter().zip(rows.chunks_exact(n.get())) {
            decomposer.decompose_slice_to(&input, &mut digits, &mut carries);
            for (i, &x) in digits.iter().enumerate() {
                for (j, &y) in row.iter().enumerate() {
                    let p = x.wrapping_mul(y);
                    let k = i + j;
                    if k < n.get() {
                        expected[k] = expected[k].wrapping_add(p)
                    } else {
                        expected[k - n.get()] = expected[k - n.get()].wrapping_sub(p)
                    }
                }
            }
        }
        let mut output = vec![u64::MAX; n.get()];
        for _ in 0..2 {
            key.external_product_to(&input, &mut output, &mut fft, &mut ordinary, &mut split);
            for (&actual, &reference) in output.iter().zip(&expected) {
                // Fixed small inputs: tolerate low-limb FFT rounding only. A
                // one-unit high-limb error is orders of magnitude above this bound.
                assert!(actual.wrapping_sub(reference).cast_signed().unsigned_abs() <= 64);
            }
        }
        let before = output.clone();
        key.external_product_add_assign(&input, &mut output, &mut fft, &mut ordinary, &mut split);
        for ((&actual, &old), &reference) in output.iter().zip(&before).zip(&expected) {
            assert!(
                actual
                    .wrapping_sub(old)
                    .wrapping_sub(reference)
                    .cast_signed()
                    .unsigned_abs()
                    <= 64
            );
        }
    }
}
#[cfg(feature = "rustfft")]
#[test]
fn rustfft_boundaries() {
    boundaries::<primus_fft::RustFftTable>();
}
#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_boundaries() {
    boundaries::<primus_fft::TfheFftTable>();
}

// Independent quadratic negacyclic product and coefficient automorphism. In
// particular, degree 3 is not self-inverse and uses Fourier conjugation.
fn product(a: &[u64], b: &[u64]) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0u64; n];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            let p = x.wrapping_mul(y);
            let k = i + j;
            if k < n {
                out[k] = out[k].wrapping_add(p)
            } else {
                out[k - n] = out[k - n].wrapping_sub(p)
            }
        }
    }
    out
}
fn automorphism(a: &[u64], degree: usize) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0; n];
    for (i, &x) in a.iter().enumerate() {
        let j = i * degree % (2 * n);
        out[j % n] = if j < n { x } else { x.wrapping_neg() };
    }
    out
}
fn fused_boundaries<Table: FftTable>() {
    use primus_lattice::ntru::FourierNtruSplitAutomorphism;
    let n = 32;
    let len = PolyLength::new(n);
    let table = Table::new(len);
    let mut fft = FftEngine::new(&table);
    for (base, levels, bits) in [(4, 16, 35), (11, 5, 40), (14, 4, 40)] {
        let basis = ApproxSignedBasis::<u64>::try_from((
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(base),
                level_count: Some(DecompositionLevelCount::new(levels)),
            },
            None,
        ))
        .unwrap();
        let half = 1u64 << (63 - base * (levels as u32 - 1));
        // Unsigned floor halving, native sign boundary and nonzero message tails.
        let input: Vec<_> = (0..n)
            .map(|i| {
                [
                    0,
                    1,
                    half - 1,
                    half,
                    half + 1,
                    u64::MAX,
                    1 << 63,
                    (1 << 63) + 1,
                ][i & 7]
                    >> 1
            })
            .collect();
        let values = [
            0,
            (1u64 << bits) - 1,
            1u64 << bits,
            u64::MAX,
            (1 << 63) + 9,
            17,
        ];
        let id: Vec<_> = (0..n * levels)
            .map(|i| values[(i / 3 + i / n) % 6])
            .collect();
        let identity = FourierNtruSplitGadget::from_coefficients(&id, &basis, bits, &mut fft);
        // R2, a non-self-inverse branch, paired trace, R4 and R8 terminal sums.
        for (degrees, include_identity) in [
            (vec![n + 1], true),
            (vec![3], true),
            (vec![3, 5, 15], false),
            ((1..4).map(|i| 1 + i * 2 * n / 4).collect(), true),
            ((1..8).map(|i| 1 + i * 2 * n / 8).collect(), true),
        ] {
            // Distinct rows expose mismatched branch keys or automorphism maps.
            let cross_rows: Vec<Vec<_>> = (0..degrees.len())
                .map(|branch| {
                    (0..n * levels)
                        .map(|i| values[(i / (branch + 2) + branch + i / n) % values.len()])
                        .collect()
                })
                .collect();
            let keys: Vec<_> = degrees
                .iter()
                .zip(&cross_rows)
                .map(|(&degree, cross)| {
                    let key =
                        FourierNtruSplitGadget::from_coefficients(cross, &basis, bits, &mut fft);
                    FourierNtruSplitAutomorphism::new(key, degree, &table)
                })
                .collect();
            let mut carries = vec![false; n];
            let mut digits = vec![0; n];
            let mut exact = vec![0u64; n];
            let mut exact_branches = vec![vec![0u64; n]; keys.len()];
            basis.init_carry_slice(&input, &mut carries);
            for (level, (decomposer, ki)) in
                basis.decomposer_iter().zip(id.chunks_exact(n)).enumerate()
            {
                decomposer.decompose_slice_to(&input, &mut digits, &mut carries);
                if include_identity {
                    for (out, value) in exact.iter_mut().zip(product(&digits, ki)) {
                        *out = out.wrapping_add(value);
                    }
                }
                for ((&degree, cross), branch) in
                    degrees.iter().zip(&cross_rows).zip(&mut exact_branches)
                {
                    let kg = &cross[level * n..(level + 1) * n];
                    for ((out, branch), value) in exact
                        .iter_mut()
                        .zip(branch)
                        .zip(product(&automorphism(&digits, degree), kg))
                    {
                        *out = out.wrapping_add(value);
                        *branch = branch.wrapping_add(value);
                    }
                }
            }
            let mut ordinary = FourierNtruExternalProductWorkspace::new(len);
            let mut split = FourierNtruSplitWorkspace::new(len);
            let mut branches = vec![primus_fft::Complex64::new(123., -99.); n * keys.len()];
            let mut output = vec![u64::MAX; n];
            let mut outputs = vec![u64::MAX; n * keys.len()];
            for _ in 0..2 {
                // Independent branch inverses reuse the same digit FFTs, but must
                // match each integer product, not the rounded sum above.
                FourierNtruSplitAutomorphism::external_products_to(
                    &keys,
                    &input,
                    &mut outputs,
                    &mut fft,
                    &mut ordinary,
                    &mut split,
                    &mut branches,
                );
                for (output, expected) in outputs.chunks_exact(n).zip(&exact_branches) {
                    for (&actual, &expected) in output.iter().zip(expected) {
                        assert!(
                            actual.wrapping_sub(expected).cast_signed().unsigned_abs() <= 1 << 16
                        );
                    }
                }

                if keys.len() == 1 {
                    keys[0].external_product_sum_to(
                        &identity,
                        &input,
                        &mut output,
                        &mut fft,
                        &mut ordinary,
                        &mut split,
                        &mut branches,
                    );
                } else {
                    FourierNtruSplitAutomorphism::external_products_sum_to(
                        &keys,
                        include_identity.then_some(&identity),
                        &input,
                        &mut output,
                        &mut fft,
                        &mut ordinary,
                        &mut split,
                        &mut branches,
                    );
                }
                for (&actual, &expected) in output.iter().zip(&exact) {
                    // Fixed inputs allow low-limb error; any unit high error fails.
                    assert!(
                        actual.wrapping_sub(expected).cast_signed().unsigned_abs()
                            <= (1 << 16) * keys.len() as u64
                    );
                }
            }
        }
    }
}
#[cfg(feature = "rustfft")]
#[test]
fn rustfft_fused_boundaries() {
    fused_boundaries::<primus_fft::RustFftTable>();
}
#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_fused_boundaries() {
    fused_boundaries::<primus_fft::TfheFftTable>();
}
