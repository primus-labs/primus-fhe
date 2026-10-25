//! Ternary selection signs, decomposition residuals and dirty-scratch reuse.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{FftEngine, FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_lattice::GlweDimension;
use primus_lattice::{
    GadgetSize, GlweSize, ggsw::Ggsw, glwe::Glwe, workspace::NttGlweTernaryCmuxWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_shape::PolyLength;

const N: usize = 32;
const Q: u32 = 132_120_577;
// Zero is last so it must copy over the preceding nontrivial result. Both
// half-ring signs, split boundaries and an interior rotation are represented.
const EXPONENTS: [usize; 8] = [1, N / 2, N - 1, N, N + 1, 3 * N / 2, 2 * N - 1, 0];

// Independent signed-index oracle, applied to every GLWE component.
fn rotate(input: &[u32], exponent: isize) -> Vec<u32> {
    let mut output = vec![0; input.len()];
    for (input, output) in input
        .as_chunks::<N>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<N>().0)
    {
        for (i, &value) in input.iter().enumerate() {
            let position = (i as isize + exponent).rem_euclid(2 * N as isize) as usize;
            output[position % N] = if position < N || value == 0 {
                value
            } else {
                Q - value
            };
        }
    }
    output
}

// Diagonal controls avoid key noise, isolating decomposition and FFT rounding.
// Keep both word widths and FFT backends: they have distinct torus conversions.
fn check_fourier_rotation<T: TorusFftValue, Table: FftTable>() {
    use primus_lattice::{ggsw::FourierGgswOwned, workspace::FourierGlweTernaryCmuxWorkspace};
    let table = Table::new(PolyLength::new(N));
    let mut fft = FftEngine::new(&table);
    let glwe_size = GlweSize::new(GlweDimension::new(2), PolyLength::new(N));
    let stride = T::MAX / T::try_from(37usize).unwrap();
    let input = Glwe::new(
        (0..glwe_size.glwe_len())
            .map(|i| {
                stride
                    .wrapping_mul(T::try_from(i).unwrap())
                    .wrapping_add(T::ONE)
            })
            .collect::<Vec<_>>(),
    );
    for levels in [(T::BITS / 8) as usize, (T::BITS / 8 - 1) as usize] {
        let basis = ApproxSignedBasis::<T>::new(
            None,
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(levels)),
        );
        let size = GadgetSize::new(glwe_size, DecompositionLevelCount::new(levels));
        let mut diagonal = Ggsw::new(vec![T::ZERO; size.ggsw_len()]);
        for row in 0..glwe_size.component_count() {
            for (level, scalar) in basis.scalar_iter().enumerate() {
                diagonal.as_mut()[(row * levels + level) * glwe_size.glwe_len() + row * N] = scalar;
            }
        }
        let mut one = FourierGgswOwned::zero(size.fourier_ggsw_len());
        diagonal.write_fourier_form(&mut one, &mut fft);
        let zero = FourierGgswOwned::zero(size.fourier_ggsw_len());
        let mut workspace = FourierGlweTernaryCmuxWorkspace::new(size);
        let mut output = Glwe::new(vec![T::MAX; glwe_size.glwe_len()]);
        // Numerical regression budget for this small ring: 2^-40 of the torus,
        // at least one integer unit, separate from the decomposition error.
        let floating_budget = T::ONE << T::BITS.saturating_sub(40);
        for secret in [1isize, -1, 0] {
            let positive = if secret == 1 { &one } else { &zero };
            let negative = if secret == -1 { &one } else { &zero };
            for exponent in EXPONENTS {
                positive.cmux_ternary_monomial_to(
                    negative,
                    &input,
                    exponent,
                    &mut output,
                    &basis,
                    &mut fft,
                    &mut workspace,
                );
                let mut expected = vec![T::ZERO; glwe_size.glwe_len()];
                for (i, &value) in input.as_ref().iter().enumerate() {
                    let position = (i as isize % N as isize + exponent as isize * secret)
                        .rem_euclid(2 * N as isize) as usize;
                    expected[i / N * N + position % N] = if position < N {
                        value
                    } else {
                        value.wrapping_neg()
                    };
                }
                let bound = if secret == 0 || exponent == 0 {
                    T::ZERO
                } else {
                    basis.approximate_error_bound() + floating_budget
                };
                for (&actual, expected) in output.as_ref().iter().zip(expected) {
                    let distance = actual
                        .wrapping_sub(expected)
                        .min(expected.wrapping_sub(actual));
                    assert!(
                        distance <= bound,
                        "s={secret}, exponent={exponent}, levels={levels}: {distance:?} > {bound:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn fourier_ternary_rotation_preserves_integer_scale_and_bounds_rounding_error() {
    check_fourier_rotation::<u32, RustFftTable>();
    check_fourier_rotation::<u64, RustFftTable>();
    check_fourier_rotation::<u32, TfheFftTable>();
    check_fourier_rotation::<u64, TfheFftTable>();
}

#[test]
fn ternary_rotation_matches_negacyclic_oracle_with_bounded_decomposition_error() {
    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let glwe_size = GlweSize::new(GlweDimension::new(2), PolyLength::new(N));
    let input = Glwe::new(
        (0..glwe_size.glwe_len())
            .map(|i| ((i as u64 * 0x9e37_79b9 + 1) % u64::from(Q)) as u32)
            .collect::<Vec<_>>(),
    );
    // Two truncation depths protect the residual on (X^a-1)C. With noiseless
    // diagonal controls each output coefficient has at most one such residual.
    for levels in [3, 2] {
        let basis = ApproxSignedBasis::new(
            Some(Q),
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(levels)),
        );
        let size = GadgetSize::new(glwe_size, DecompositionLevelCount::new(levels));
        let mut one = Ggsw::zero(size.ggsw_len());
        for row in 0..glwe_size.component_count() {
            for (level, scalar) in basis.scalar_iter().enumerate() {
                one.as_mut()[(row * levels + level) * glwe_size.glwe_len() + row * N] = scalar;
            }
        }
        let one = one.into_ntt_form(&ntt);
        let zero = Ggsw::new(vec![0u32; size.ggsw_len()]).into_ntt_form(&ntt);
        let mut workspace = NttGlweTernaryCmuxWorkspace::new(size);
        let mut output = Glwe::new(vec![Q - 1; glwe_size.glwe_len()]);
        // Reuse dirty output/scratch across signs and wrap back to exponent zero.
        for secret in [1, -1, 0] {
            let positive = if secret == 1 { &one } else { &zero };
            let negative = if secret == -1 { &one } else { &zero };
            for exponent in EXPONENTS {
                positive.cmux_ternary_monomial_to(
                    negative,
                    &input,
                    exponent,
                    &mut output,
                    &basis,
                    modulus,
                    &ntt,
                    &mut workspace,
                );
                let expected = rotate(input.as_ref(), exponent as isize * secret);
                let bound = if secret == 0 || exponent == 0 {
                    0
                } else {
                    basis.approximate_error_bound()
                };
                for (&actual, expected) in output.as_ref().iter().zip(expected) {
                    assert!(actual < Q);
                    let distance = actual.abs_diff(expected);
                    assert!(
                        distance.min(Q - distance) <= bound,
                        "s={secret}, exponent={exponent}, levels={levels}: {actual} != {expected}"
                    );
                }
            }
        }
    }
}

#[test]
fn ngsw_ternary_rotation_matches_negacyclic_oracle() {
    use primus_lattice::{ngsw::Ngsw, ntru::Ntru, workspace::NttNtruCmuxWorkspace};
    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::new(PolyLength::new(N), modulus).unwrap();
    let input = Ntru::new(
        (0..N)
            .map(|i| ((i as u64 * 0x9e37_79b9 + 1) % u64::from(Q)) as u32)
            .collect::<Vec<_>>(),
    );
    for levels in [3, 2] {
        let basis = ApproxSignedBasis::new(
            Some(Q),
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(levels)),
        );
        // Noiseless NGSW(1): each coefficient row is the constant gadget scalar.
        let mut one = Ngsw::zero(N * levels);
        for (level, scalar) in basis.scalar_iter().enumerate() {
            one.as_mut()[level * N] = scalar;
        }
        let one = one.into_ntt_form(&ntt);
        let zero = Ngsw::new(vec![0u32; N * levels]).into_ntt_form(&ntt);
        let mut workspace =
            NttNtruCmuxWorkspace::new(PolyLength::new(N), DecompositionLevelCount::new(levels));
        let mut output = Ntru::new(vec![Q - 1; N]);
        for secret in [1, -1, 0] {
            let positive = if secret == 1 { &one } else { &zero };
            let negative = if secret == -1 { &one } else { &zero };
            // Traverse sign and wrap boundaries, then reuse dirty scratch
            // for the public zero-exponent copy path.
            for exponent in EXPONENTS {
                positive.cmux_ternary_monomial_to(
                    negative,
                    &input,
                    exponent,
                    &mut output,
                    &basis,
                    modulus,
                    &ntt,
                    &mut workspace,
                );
                let expected = rotate(input.as_ref(), exponent as isize * secret);
                let bound = if secret == 0 || exponent == 0 {
                    0
                } else {
                    basis.approximate_error_bound()
                };
                for (&actual, expected) in output.as_ref().iter().zip(expected) {
                    assert!(actual < Q);
                    let distance = actual.abs_diff(expected);
                    assert!(
                        distance.min(Q - distance) <= bound,
                        "s={secret}, exponent={exponent}, levels={levels}: {actual} != {expected}"
                    );
                }
            }
        }
    }
}
