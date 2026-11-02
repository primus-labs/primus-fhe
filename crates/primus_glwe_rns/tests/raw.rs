//! Codec-free encryption and phase shares checked without Primus NTT/CRT oracles.

use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    CrtGlweEncryptionParameters, DcrtGlweCiphertext, DcrtGlweDomain, DcrtGlweSecretKey,
    GlweSecretKey, RnsDomainError, SecretKeyDistr,
};
use primus_integer::{AsFrom, FheUint};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, NttTable, U32NttTable, U64NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64
}

fn pow_mod(mut value: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul_mod(result, value, modulus);
        }
        value = mul_mod(value, value, modulus);
        exponent >>= 1;
    }
    result
}

// Built-in tables choose the smallest primitive 2N-th root. Find it by field
// exponentiation, then enumerate all odd powers; no table roots are consulted.
fn primitive_root(n: usize, modulus: u64) -> u64 {
    let root = (2..modulus)
        .map(|candidate| pow_mod(candidate, (modulus - 1) / (2 * n as u64), modulus))
        .find(|&candidate| pow_mod(candidate, n as u64, modulus) == modulus - 1)
        .unwrap();
    let step = mul_mod(root, root, modulus);
    std::iter::successors(Some(root), |&value| Some(mul_mod(value, step, modulus)))
        .take(n)
        .min()
        .unwrap()
}

fn evaluation_points(n: usize, modulus: u64) -> Vec<u64> {
    let root = primitive_root(n, modulus);
    (0..n)
        .map(|index| {
            let reversed = index.reverse_bits() >> (usize::BITS - n.trailing_zeros());
            pow_mod(root, (2 * reversed + 1) as u64, modulus)
        })
        .collect()
}

// Direct O(N^2) evaluation/interpolation implements the documented negacyclic
// transform convention, independently of the optimized forward/inverse kernels.
fn direct_transform(coefficients: &[u64], modulus: u64) -> Vec<u64> {
    let n = coefficients.len();
    evaluation_points(n, modulus)
        .into_iter()
        .map(|point| {
            coefficients.iter().rev().fold(0, |acc, &coefficient| {
                (mul_mod(acc, point, modulus) + coefficient) % modulus
            })
        })
        .collect()
}

fn direct_inverse(evaluations: &[u64], modulus: u64) -> Vec<u64> {
    let n = evaluations.len();
    let inverse_n = pow_mod(n as u64, modulus - 2, modulus);
    let inverse_points: Vec<_> = evaluation_points(n, modulus)
        .into_iter()
        .map(|point| pow_mod(point, modulus - 2, modulus))
        .collect();
    (0..n)
        .map(|degree| {
            let sum =
                evaluations
                    .iter()
                    .zip(&inverse_points)
                    .fold(0, |acc, (&value, &inverse_point)| {
                        let term = mul_mod(
                            value,
                            pow_mod(inverse_point, degree as u64, modulus),
                            modulus,
                        );
                        (acc + term) % modulus
                    });
            mul_mod(sum, inverse_n, modulus)
        })
        .collect()
}

fn negacyclic_product(mask: &[u64], secret: &[i64], modulus: u64) -> Vec<u64> {
    let n = mask.len();
    let mut output = vec![0i128; n];
    for (left, &coefficient) in mask.iter().enumerate() {
        for (right, &secret_coefficient) in secret.iter().enumerate() {
            let product = i128::from(coefficient) * i128::from(secret_coefficient);
            let degree = left + right;
            output[degree % n] += if degree < n { product } else { -product };
        }
    }
    output
        .into_iter()
        .map(|coefficient| coefficient.rem_euclid(i128::from(modulus)) as u64)
        .collect()
}

fn coefficient_phase(ciphertext: &[u64], secret: &[i64], n: usize, moduli: &[u64]) -> Vec<u64> {
    let poly_len = n * moduli.len();
    let rank = secret.len() / n;
    let mut phase = Vec::with_capacity(poly_len);
    for (limb, &q) in moduli.iter().enumerate() {
        let mut coefficients = direct_inverse(&ciphertext[rank * poly_len + limb * n..][..n], q);
        for component in 0..rank {
            let mask = direct_inverse(&ciphertext[component * poly_len + limb * n..][..n], q);
            let product = negacyclic_product(&mask, &secret[component * n..][..n], q);
            for (coefficient, product) in coefficients.iter_mut().zip(product) {
                *coefficient = (*coefficient + q - product) % q;
            }
        }
        phase.extend(coefficients);
    }
    phase
}

fn recover_coefficients<T: FheUint>(values: &[T], n: usize, moduli: &[u64]) -> Vec<u64> {
    values
        .chunks_exact(n)
        .zip(moduli)
        .flat_map(|(limb, &q)| {
            direct_inverse(
                &limb
                    .iter()
                    .map(|&value| value.as_into())
                    .collect::<Vec<_>>(),
                q,
            )
        })
        .collect()
}

// Two independent machine-word residues can represent Q wider than u64.
fn centered_crt_pair(first: u64, second: u64, moduli: &[u64]) -> i128 {
    let [q0, q1] = <[u64; 2]>::try_from(moduli).unwrap();
    let correction = mul_mod(
        (second + q1 - first % q1) % q1,
        pow_mod(q0 % q1, q1 - 2, q1),
        q1,
    );
    let value = u128::from(first) + u128::from(q0) * u128::from(correction);
    let product = u128::from(q0) * u128::from(q1);
    value as i128
        - if value > product / 2 {
            product as i128
        } else {
            0
        }
}

fn check_raw<T, Table>(moduli: [T; 2])
where
    T: FheUint,
    BarrettModulus<T>: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let values: Vec<u64> = moduli.iter().map(|&q| q.as_into()).collect();
    let moduli = moduli.map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    for (rank, n, error) in [
        (1, 32, ErrorDistribution::CenteredBinomial { eta: 1 }),
        (2, 64, ErrorDistribution::CenteredBinomial { eta: 21 }),
        (
            2,
            32,
            ErrorDistribution::Gaussian {
                standard_deviation: 3.2,
            },
        ),
    ] {
        let size = RnsGlweSize::new(
            GlweSize::new(GlweDimension::new(rank), PolyLength::new(n)),
            values.len(),
        );
        let parameters = CrtGlweEncryptionParameters::try_with_error_distribution(
            size,
            &base,
            SecretKeyDistr::SparseTernary,
            error,
        )
        .unwrap();
        let table = DcrtTable::<Table>::new(PolyLength::new(n), &moduli).unwrap();
        let domain = DcrtGlweDomain::try_new(&parameters, &base, &table).unwrap();
        let secret: Vec<i64> = (0..rank * n).map(|i| (i % 3) as i64 - 1).collect();
        let coefficient_key = GlweSecretKey::<T>::new(
            secret
                .iter()
                .map(|&value| T::SignedInteger::as_from(value))
                .collect(),
            size.glwe_size(),
            SecretKeyDistr::SparseTernary,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
        let context = key.try_bind_raw(&domain).unwrap();
        // Deliberately different per-limb representatives detect accidental limb
        // copying and implicit BFV scaling, without requiring any t or gamma.
        let message: Vec<T> = values
            .iter()
            .flat_map(|&q| {
                (0..n).map(move |i| {
                    T::as_from(match i % 6 {
                        0 => 0,
                        1 => 1,
                        2 => q - 1,
                        3 => q / 2,
                        4 => q / 2 + 1,
                        _ => (7 * i as u64 + 3) % q,
                    })
                })
            })
            .collect();
        let encoded = CrtPolynomial::new(message.clone());
        let mut ciphertext = DcrtGlweCiphertext::new(vec![T::ONE; size.rns_glwe_len()]);
        let mut zero = DcrtGlweCiphertext::new(vec![T::ONE; size.rns_glwe_len()]);
        let seed = 0x524157 + rank as u64;
        let mut rng = StdRng::seed_from_u64(seed);
        let mut zero_rng = StdRng::seed_from_u64(seed);
        context.encrypt_encoded_crt_to(&encoded.as_view(), &mut ciphertext.as_mut_view(), &mut rng);
        context.encrypt_zeros_to(&mut zero, &mut zero_rng);
        assert_eq!(rng.next_u64(), zero_rng.next_u64());
        let poly_len = size.rns_poly_len();
        assert_eq!(
            &ciphertext.as_ref()[..rank * poly_len],
            &zero.as_ref()[..rank * poly_len]
        );
        for (limb, &q) in values.iter().enumerate() {
            let expected = direct_transform(
                &message[limb * n..][..n]
                    .iter()
                    .map(|&value| value.as_into())
                    .collect::<Vec<_>>(),
                q,
            );
            let start = rank * poly_len + limb * n;
            let actual: Vec<u64> = ciphertext.as_ref()[start..][..n]
                .iter()
                .zip(&zero.as_ref()[start..][..n])
                .map(|(&left, &right)| {
                    let left: u64 = left.as_into();
                    let right: u64 = right.as_into();
                    (left + q - right) % q
                })
                .collect();
            assert_eq!(
                actual, expected,
                "encoded phase must be added exactly once without delta"
            );
        }
        let ciphertext_u64: Vec<u64> = ciphertext
            .as_ref()
            .iter()
            .map(|&value| value.as_into())
            .collect();
        let expected = coefficient_phase(&ciphertext_u64, &secret, n, &values);
        let mut phase = DcrtPolynomial::new(vec![T::ONE; poly_len]);
        context.phase_to(&ciphertext.as_view(), &mut phase.as_mut_view());
        assert_eq!(recover_coefficients(phase.as_ref(), n, &values), expected);
        let errors: Vec<u64> = expected
            .iter()
            .zip(&message)
            .enumerate()
            .map(|(i, (&phase, &message))| {
                let message: u64 = message.as_into();
                let q = values[i / n];
                (phase + q - message) % q
            })
            .collect();
        let bound = i128::from(parameters.noise_distribution().maximum_magnitude());
        for i in 0..n {
            let error = centered_crt_pair(errors[i], errors[n + i], &values);
            assert!(
                error.abs() <= bound,
                "coefficient noise must be the same integer in every limb"
            );
        }
        context.phase_to(&zero, &mut phase);
        let zero_phase = recover_coefficients(phase.as_ref(), n, &values);
        assert_eq!(
            zero_phase,
            coefficient_phase(
                &zero
                    .as_ref()
                    .iter()
                    .map(|&value| value.as_into())
                    .collect::<Vec<_>>(),
                &secret,
                n,
                &values
            )
        );
        assert_eq!(zero_phase, errors);
    }
}

#[test]
fn raw_u32_encryption_and_phase_match_integer_oracles() {
    check_raw::<u32, U32NttTable>([998_244_353, 1_004_535_809]);
}

#[test]
fn raw_u64_encryption_and_phase_match_integer_oracles() {
    check_raw::<u64, U64NttTable>([1_125_899_906_826_241, 1_125_899_906_629_633]);
}

fn check_shares<T, Table>(values: [T; 2], rank: usize)
where
    T: FheUint,
    BarrettModulus<T>: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let n = 32;
    let moduli = values.map(BarrettModulus::new);
    let values: Vec<u64> = values.iter().map(|&value| value.as_into()).collect();
    let base = RNSBase::new(&moduli).unwrap();
    let size = RnsGlweSize::new(
        GlweSize::new(GlweDimension::new(rank), PolyLength::new(n)),
        2,
    );
    let parameters =
        CrtGlweEncryptionParameters::new(size, &base, SecretKeyDistr::SparseTernary, 3.2);
    let table = DcrtTable::<Table>::new(PolyLength::new(n), &moduli).unwrap();
    let domain = DcrtGlweDomain::try_new(&parameters, &base, &table).unwrap();
    let secrets: Vec<Vec<i64>> = (0..3)
        .map(|party| {
            (0..rank * n)
                .map(|i| {
                    if i % 3 == party {
                        if i % 2 == 0 { 1 } else { -1 }
                    } else {
                        0
                    }
                })
                .collect()
        })
        .collect();
    let aggregate: Vec<i64> = (0..rank * n)
        .map(|i| secrets.iter().map(|secret| secret[i]).sum())
        .collect();
    let mut ciphertext_data = Vec::new();
    for component in 0..=rank {
        for &q in &values {
            let coefficients: Vec<u64> = (0..n)
                .map(|i| ((i + 1) * (component + 2)) as u64 % q)
                .collect();
            ciphertext_data.extend(
                direct_transform(&coefficients, q)
                    .into_iter()
                    .map(T::as_from),
            );
        }
    }
    let ciphertext = DcrtGlweCiphertext::new(ciphertext_data);
    let expected = coefficient_phase(
        &ciphertext
            .as_ref()
            .iter()
            .map(|&value| value.as_into())
            .collect::<Vec<_>>(),
        &aggregate,
        n,
        &values,
    );
    let mut partial_sum = vec![0u64; size.rns_poly_len()];
    let mut one_full_sum = partial_sum.clone();
    for (party, secret) in secrets.iter().enumerate() {
        let key = GlweSecretKey::<T>::new(
            secret
                .iter()
                .map(|&value| T::SignedInteger::as_from(value))
                .collect(),
            size.glwe_size(),
            SecretKeyDistr::SparseTernary,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, &table);
        let context = key.try_bind_raw(&domain).unwrap();
        let mut share = DcrtPolynomial::new(vec![T::ONE; size.rns_poly_len()]);
        context.partial_phase_to(&ciphertext, &mut share);
        let partial = recover_coefficients(share.as_ref(), n, &values);
        let bodyless: Vec<u64> = ciphertext
            .as_ref()
            .iter()
            .map(|&value| value.as_into())
            .enumerate()
            .map(|(i, value)| {
                if i < rank * size.rns_poly_len() {
                    value
                } else {
                    0
                }
            })
            .collect();
        assert_eq!(partial, coefficient_phase(&bodyless, secret, n, &values));
        for (i, &value) in partial.iter().enumerate() {
            partial_sum[i] = (partial_sum[i] + value) % values[i / n];
        }
        if party == 0 {
            context.phase_to(&ciphertext, &mut share);
        }
        for (i, value) in recover_coefficients(share.as_ref(), n, &values)
            .into_iter()
            .enumerate()
        {
            one_full_sum[i] = (one_full_sum[i] + value) % values[i / n];
        }
    }
    let body = recover_coefficients(
        &ciphertext.as_ref()[rank * size.rns_poly_len()..],
        n,
        &values,
    );
    for (i, &value) in body.iter().enumerate() {
        partial_sum[i] = (partial_sum[i] + value) % values[i / n];
    }
    assert_eq!(
        partial_sum, expected,
        "add the body exactly once after summing negative-mask shares"
    );
    assert_eq!(
        one_full_sum, expected,
        "one full phase plus the remaining partial phases is equivalent"
    );
}

#[test]
fn additive_phase_shares_exclude_the_body_and_preserve_the_negative_sign() {
    check_shares::<u32, U32NttTable>([257, 769], 1);
    check_shares::<u64, U64NttTable>([1_125_899_906_826_241, 1_125_899_906_629_633], 2);
}

#[test]
fn raw_binding_rejects_foreign_shapes_and_ordered_bases() {
    let n = PolyLength::new(32);
    let moduli = [257u32, 769].map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), n), 2);
    let parameters =
        CrtGlweEncryptionParameters::new(size, &base, SecretKeyDistr::SparseTernary, 3.2);
    let table = DcrtTable::<U32NttTable>::new(n, &moduli).unwrap();
    let domain = DcrtGlweDomain::try_new(&parameters, &base, &table).unwrap();
    let reversed_moduli = [moduli[1], moduli[0]];
    let reversed_base = RNSBase::new(&reversed_moduli).unwrap();
    let reversed_table = DcrtTable::<U32NttTable>::new(n, &reversed_moduli).unwrap();
    assert!(matches!(
        DcrtGlweDomain::try_new(&parameters, &reversed_base, &reversed_table),
        Err(RnsDomainError::ModulusOrderMismatch { .. })
    ));
    let short_base = RNSBase::new(&moduli[..1]).unwrap();
    assert!(matches!(
        DcrtGlweDomain::try_new(&parameters, &short_base, &table),
        Err(RnsDomainError::ModuliCountMismatch { .. })
    ));
    let wrong_length_table = DcrtTable::<U32NttTable>::new(PolyLength::new(64), &moduli).unwrap();
    assert!(matches!(
        DcrtGlweDomain::try_new(&parameters, &base, &wrong_length_table),
        Err(RnsDomainError::PolynomialLengthMismatch { .. })
    ));
    for (rank, key_table, expected_dimension) in [(2, &table, true), (1, &reversed_table, false)] {
        let key = GlweSecretKey::<u32>::new(
            vec![0; rank * n.get()],
            GlweSize::new(GlweDimension::new(rank), n),
            SecretKeyDistr::SparseTernary,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, key_table);
        let error = key.try_bind_raw(&domain).err().unwrap();
        if expected_dimension {
            assert!(matches!(error, RnsDomainError::DimensionMismatch { .. }));
        } else {
            assert!(matches!(error, RnsDomainError::ModulusOrderMismatch { .. }));
        }
    }
}

#[test]
fn malformed_raw_layouts_are_rejected_before_writes_or_randomness() {
    let moduli = [257u64, 769].map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(2), PolyLength::new(32)), 2);
    let parameters =
        CrtGlweEncryptionParameters::new(size, &base, SecretKeyDistr::SparseTernary, 3.2);
    let table = DcrtTable::<U64NttTable>::new(PolyLength::new(32), &moduli).unwrap();
    let domain = DcrtGlweDomain::try_new(&parameters, &base, &table).unwrap();
    let key = GlweSecretKey::<u64>::new(
        vec![0; size.glwe_size().mask_len()],
        size.glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, &table);
    let context = key.try_bind_raw(&domain).unwrap();
    for (message_len, output_len) in [
        (size.rns_poly_len() - 1, size.rns_glwe_len()),
        (size.rns_poly_len(), size.rns_glwe_len() + 1),
    ] {
        let message = CrtPolynomial::new(vec![1; message_len]);
        let mut output = DcrtGlweCiphertext::new(vec![7; output_len]);
        let original = output.clone();
        let mut rng = StdRng::seed_from_u64(41);
        let mut untouched_rng = StdRng::seed_from_u64(41);
        assert!(
            catch_unwind(AssertUnwindSafe(|| context.encrypt_encoded_crt_to(
                &message,
                &mut output,
                &mut rng
            )))
            .is_err()
        );
        assert_eq!(output.as_ref(), original.as_ref());
        assert_eq!(rng.next_u64(), untouched_rng.next_u64());
    }
    for (input_len, output_len) in [
        (size.rns_glwe_len() - 1, size.rns_poly_len()),
        (size.rns_glwe_len(), size.rns_poly_len() + 1),
    ] {
        let input = DcrtGlweCiphertext::new(vec![1; input_len]);
        for partial in [false, true] {
            let mut output = DcrtPolynomial::new(vec![7; output_len]);
            let original = output.clone();
            assert!(
                catch_unwind(AssertUnwindSafe(|| if partial {
                    context.partial_phase_to(&input, &mut output);
                } else {
                    context.phase_to(&input, &mut output);
                }))
                .is_err()
            );
            assert_eq!(output, original);
        }
    }
}
