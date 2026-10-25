#![cfg(feature = "rns")]

use primus_encoding::{
    BfvRnsCodec, BfvRnsCodecError,
    PlaintextEmbedding::{Centered, Unsigned},
};
use primus_modulus::BarrettModulus;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_rns::RNSBase;

// Construction checks the BFV conditions beyond a valid ciphertext RNS base.
#[test]
fn fallible_construction_reports_modulus_and_recovery_errors() {
    use BfvRnsCodecError::*;
    for (t, moduli, gamma, expected) in [
        (
            3,
            &[17u64, 19][..],
            7,
            AuxiliaryModulusTooSmall {
                gamma: 7,
                lower_bound: 8,
            },
        ),
        (3, &[17, 19][..], 9, NonCoprimeModuli { lhs: 3, rhs: 9 }),
        (3, &[9][..], 11, NonCoprimeModuli { lhs: 9, rhs: 3 }),
        (3, &[17, 19][..], 17, NonCoprimeModuli { lhs: 17, rhs: 17 }),
        (
            19,
            &[97, 17][..],
            101,
            CiphertextModulusTooSmall {
                modulus: 17,
                plain_modulus: 19,
                index: 1,
            },
        ),
        (7, &[17][..], 101, InsufficientScaleRecovery),
    ] {
        let base = RNSBase::new(
            &moduli
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let result = BfvRnsCodec::try_new(BarrettModulus::new(t), base, BarrettModulus::new(gamma));
        assert_eq!(result.err(), Some(expected));
    }
}

// Check the last accepted integer noise magnitude and actual recovery at both
// noise signs. Multi-modulus cases require products wider than the coefficient word.
#[test]
fn noise_recovery_bound_matches_integer_oracle() {
    fn check<T: primus_integer::FheUint>(moduli: &[T], t: T, gamma: T) {
        let q: u128 = moduli.iter().map(|&qi| -> u128 { qi.as_into() }).product();
        let t_value: u128 = t.as_into();
        let gamma_value: u128 = gamma.as_into();
        let maximum_word: u128 = T::MAX.as_into();
        let base = RNSBase::new(
            &moduli
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let codec = BfvRnsCodec::new(BarrettModulus::new(t), base, BarrettModulus::new(gamma));
        let messages = [0, t_value / 2, t_value - 1].map(T::as_from);
        let mut output = Polynomial::new(vec![T::ZERO; messages.len()]);
        let mut scratch = vec![T::ZERO; codec.decode_scratch_len(messages.len())];
        for embedding in [Unsigned, Centered] {
            let maximum_lift = if embedding == Unsigned {
                t_value - 1
            } else {
                t_value / 2
            };
            // Independent u128 oracle: take the largest integer scaled error
            // strictly below the rounding threshold, then remove encoding drift.
            let scaled_phase_limit =
                (q * (gamma_value - 2 * moduli.len() as u128) - 1) / (2 * gamma_value);
            let noise_limit = (scaled_phase_limit - (q % t_value) * maximum_lift) / t_value;
            assert!(noise_limit < maximum_word);
            for noise in [0, noise_limit, noise_limit + 1, maximum_word] {
                let noise_in_word = T::as_from(noise);
                let expected = if noise <= noise_limit {
                    Ok(())
                } else {
                    Err(BfvRnsCodecError::InsufficientNoiseRecovery {
                        maximum_noise_magnitude: noise_in_word,
                        embedding,
                    })
                };
                assert_eq!(
                    codec.validate_noise_bound(noise_in_word, embedding),
                    expected
                );
            }
            for noise in [-(noise_limit as i128), noise_limit as i128] {
                let residues = moduli
                    .iter()
                    .flat_map(|&qi| {
                        let qi: u128 = qi.as_into();
                        messages.iter().map(move |&message| {
                            let message: u128 = message.as_into();
                            let lift = if embedding == Centered && message >= t_value.div_ceil(2) {
                                message as i128 - t_value as i128
                            } else {
                                message as i128
                            };
                            T::as_from(
                                ((q / t_value) as i128 * lift + noise).rem_euclid(qi as i128),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                codec.decode_coeffs_to(
                    &mut CrtPolynomial::new(residues),
                    &mut output,
                    &mut scratch,
                );
                assert_eq!(
                    output.as_ref(),
                    messages,
                    "embedding={embedding:?}, noise={noise}"
                );
            }
        }
    }

    check(&[97u32], 3, 13);
    check(&[97u32], 3, 101);
    check(&[134_215_681u32, 134_176_769], 1 << 25, 536_870_909);
    check(&[4_294_967_311u64, 4_294_967_357], 1 << 16, 1_048_573);
}

#[test]
fn floor_scaling_and_noisy_decode_match_integer_oracle() {
    for (moduli, t, gamma) in [
        (&[97u64][..], 3, 65537),
        (&[17u64, 19][..], 3, 65537),
        (&[17, 19][..], 2, 65537),
        (&[97, 193][..], 7, 65537),
        (
            &[1125899906826241, 1125899906629633][..],
            12289,
            2305843009213554689,
        ), // Q exceeds u64; the independent oracle still fits i128.
    ] {
        let q: u128 = moduli.iter().map(|&qi| u128::from(qi)).product();
        let delta = q / u128::from(t);
        let base = RNSBase::new(
            &moduli
                .iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let codec = BfvRnsCodec::new(BarrettModulus::new(t), base, BarrettModulus::new(gamma));
        let input = Polynomial::new(if t <= 7 {
            (0..t).collect::<Vec<_>>()
        } else {
            // Include full SIMD vectors and a scalar tail when SIMD is enabled.
            (0..17)
                .map(|i| [0, 1, t / 2, t.div_ceil(2), t - 1][i % 5])
                .collect()
        });
        let messages = input.as_ref();
        let n = messages.len();
        assert_eq!(
            codec.decode_scratch_len(n),
            if moduli.len() == 1 {
                0
            } else {
                n * moduli.len()
            }
        );
        let mut scratch = vec![0; codec.decode_scratch_len(n)];
        let mut output = Polynomial::<Vec<u64>>::zero(n);
        for embedding in [Unsigned, Centered] {
            let expected: Vec<u64> = moduli
                .iter()
                .flat_map(|&qi| {
                    messages.iter().map(move |&m| {
                        let lift = if embedding == Centered && m >= t.div_ceil(2) {
                            i128::from(m) - i128::from(t)
                        } else {
                            i128::from(m)
                        };
                        (lift * delta as i128).rem_euclid(i128::from(qi)) as u64
                    })
                })
                .collect();
            let mut encoded = CrtPolynomial::<Vec<u64>>::zero(n * moduli.len());
            codec.encode_coeffs_to(&input, &mut encoded, embedding);
            assert_eq!(
                encoded.as_ref(),
                expected,
                "t={t}, Q={q}, embedding={embedding:?}"
            );
            let mut acc = CrtPolynomial::new(
                moduli
                    .iter()
                    .flat_map(|&qi| vec![qi - 1; n])
                    .collect::<Vec<_>>(),
            );
            codec.add_encode_coeffs_assign(&input, &mut acc, embedding);
            for (i, &value) in acc.as_ref().iter().enumerate() {
                assert_eq!(value, (expected[i] + moduli[i / n] - 1) % moduli[i / n]);
            }
            for noise in [-1i128, 0, 1] {
                let mut phase = CrtPolynomial::new(
                    expected
                        .iter()
                        .enumerate()
                        .map(|(i, &x)| {
                            (i128::from(x) + noise).rem_euclid(i128::from(moduli[i / n])) as u64
                        })
                        .collect::<Vec<_>>(),
                );
                codec.decode_coeffs_to(&mut phase, &mut output, &mut scratch);
                assert_eq!(
                    output.as_ref(),
                    input.as_ref(),
                    "t={t}, embedding={embedding:?}, noise={noise}"
                );
            }
        }
    }
}

#[test]
fn rejects_invalid_rns_boundaries_before_writing() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let base = RNSBase::new(&[17u64, 19].map(BarrettModulus::new)).unwrap();
    let codec = BfvRnsCodec::new(BarrettModulus::new(3), base, BarrettModulus::new(65537));
    for (input, len) in [(&[0][..], 1), (&[0][..], 3), (&[0, 3][..], 4)] {
        let mut output = CrtPolynomial::new(vec![9; len]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| codec.encode_coeffs_to(
                &Polynomial::new(input),
                &mut output,
                Centered
            )))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![9; len]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| codec.add_encode_coeffs_assign(
                &Polynomial::new(input),
                &mut output,
                Centered
            )))
            .is_err()
        );
        assert_eq!(output.as_ref(), vec![9; len]);
    }
    for (input_len, scratch_len) in [(1, 2), (3, 2), (2, 1), (2, 3)] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| codec.decode_coeffs_to(
                &mut CrtPolynomial::<Vec<u64>>::zero(input_len),
                &mut Polynomial::<Vec<u64>>::zero(1),
                &mut vec![0; scratch_len]
            )))
            .is_err()
        );
    }
}
