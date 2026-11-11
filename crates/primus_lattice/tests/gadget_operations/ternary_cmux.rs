//! Ternary selection signs, decomposition residuals and dirty-scratch reuse.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_lattice::{
    GadgetSize, GlweSize, ggsw::Ggsw, glwe::Glwe, workspace::NttGlweTernaryCmuxWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};

use super::{N, POLY_LENGTH, unit_ggsw, unit_ngsw};

const Q: u32 = 132_120_577;
// Zero is last so it must copy over the preceding nontrivial result. Both
// half-ring signs, split boundaries and an interior rotation are represented.
const EXPONENTS: [usize; 8] = [1, N / 2, N - 1, N, N + 1, 3 * N / 2, 2 * N - 1, 0];

// Independent signed-index oracle, applied to every ciphertext component.
fn rotate<T: FheUint>(input: &[T], exponent: isize, negate: impl Fn(T) -> T) -> Vec<T> {
    let mut output = vec![T::ZERO; input.len()];
    for (input, output) in input
        .as_chunks::<N>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<N>().0)
    {
        for (i, &value) in input.iter().enumerate() {
            let position = (i as isize + exponent).rem_euclid(2 * N as isize) as usize;
            output[position % N] = if position < N { value } else { negate(value) };
        }
    }
    output
}

fn rotate_mod_q(input: &[u32], exponent: isize) -> Vec<u32> {
    rotate(
        input,
        exponent,
        |value| if value == 0 { 0 } else { Q - value },
    )
}

// Diagonal controls avoid key noise, isolating decomposition and FFT rounding.
// Keep both word widths and FFT backends: they have distinct torus conversions.
pub(super) fn check_fourier<T: TorusFftValue, Table: FftTable>(table: &Table) {
    use primus_lattice::{ggsw::FourierGgswOwned, workspace::FourierGlweTernaryCmuxWorkspace};
    let mut fft = FftEngine::new(table);
    let glwe_size = GlweSize::new(GlweDimension::new(2), POLY_LENGTH);
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
        let diagonal = unit_ggsw(size, &basis);
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
                let expected = rotate(input.as_ref(), exponent as isize * secret, |value| {
                    value.wrapping_neg()
                });
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
fn ternary_rotation_matches_negacyclic_oracle_with_bounded_decomposition_error() {
    let modulus = BarrettModulus::new(Q);
    let ntt = UintNttTable::new(POLY_LENGTH, modulus).unwrap();
    let glwe_size = GlweSize::new(GlweDimension::new(2), POLY_LENGTH);
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
        let one = unit_ggsw(size, &basis).into_ntt_form(&ntt);
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
                let expected = rotate_mod_q(input.as_ref(), exponent as isize * secret);
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
    let ntt = UintNttTable::new(POLY_LENGTH, modulus).unwrap();
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
        let one = unit_ngsw(&basis).into_ntt_form(&ntt);
        let zero = Ngsw::new(vec![0u32; N * levels]).into_ntt_form(&ntt);
        let mut workspace =
            NttNtruCmuxWorkspace::new(POLY_LENGTH, DecompositionLevelCount::new(levels));
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
                let expected = rotate_mod_q(input.as_ref(), exponent as isize * secret);
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
