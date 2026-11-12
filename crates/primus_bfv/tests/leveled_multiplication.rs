//! External-Q restoration, independent integer residuals and real encrypted chains.
use dashu_int::IBig;
use primus_bfv::evaluation::{
    BfvLeveledMultiplication, BfvModulusSwitch, BfvMultiplication, BfvMultiplicationBackend,
};
use primus_bfv::{BfvCiphertext, BfvClient, BfvContext, BfvParameters};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const T: u64 = 193;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];
const P: [u64; 2] = [1_152_921_504_606_830_593, 1_152_921_504_606_748_673];

fn context(t: u64, qs: &[u64]) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(t),
            &qs.iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        qs.len(),
    )
    .unwrap()
}
fn config() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    }
}
fn total(qs: &[u64]) -> IBig {
    qs.iter().fold(IBig::ONE, |a, &q| a * q)
}
fn modulo(x: &IBig, q: &IBig) -> IBig {
    let value = x % q;
    if value < IBig::ZERO { value + q } else { value }
}
fn center(x: &IBig, q: &IBig) -> IBig {
    let value = modulo(x, q);
    if value > q / 2u64 { value - q } else { value }
}
fn nearest(x: &IBig, q: &IBig) -> IBig {
    if x < &IBig::ZERO {
        -((-x + q / 2u64) / q)
    } else {
        (x + q / 2u64) / q
    }
}
fn pow(mut x: u64, mut e: u64, q: u64) -> u64 {
    let mut result = 1;
    while e != 0 {
        if e & 1 != 0 {
            result = (result as u128 * x as u128 % q as u128) as u64;
        }
        x = (x as u128 * x as u128 % q as u128) as u64;
        e >>= 1;
    }
    result
}
fn convolution(a: &[IBig], b: &[IBig]) -> Vec<IBig> {
    let mut result = vec![IBig::ZERO; N];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            if i + j < N {
                result[i + j] += x * y;
            } else {
                result[i + j - N] -= x * y;
            }
        }
    }
    result
}
fn plaintext_product(a: &[u64], b: &[u64]) -> Vec<u64> {
    convolution(
        &a.iter().copied().map(IBig::from).collect::<Vec<_>>(),
        &b.iter().copied().map(IBig::from).collect::<Vec<_>>(),
    )
    .iter()
    .map(|x| u64::try_from(modulo(x, &IBig::from(T))).unwrap())
    .collect()
}

// Independent HPS scalar rule: use the exact rational numerator as one integer,
// rather than the production RNS converter or its modular dot-product code.
fn hps_scaled(x: &IBig, qs: &[u64], p: &IBig) -> IBig {
    let q = total(qs);
    let correction = qs.iter().fold(IBig::ZERO, |sum, &qi| {
        let hat = &q / qi;
        let inverse = pow(
            u64::try_from(modulo(&hat, &IBig::from(qi))).unwrap(),
            qi - 2,
            qi,
        );
        let digit = modulo(&(-p * x * inverse), &IBig::from(qi));
        sum + digit * hat
    });
    let numerator = p * x + correction;
    assert_eq!(&numerator % &q, IBig::ZERO);
    center(&(numerator / q), p)
}
fn c0_ciphertext(context: &BfvContext, level: usize, c0: &[IBig]) -> BfvCiphertext<Vec<u64>> {
    let mut result = context.new_ciphertext(level);
    for ((&q, table), limb) in Q[..Q.len() - level].iter().zip(context.table().iter()).zip(
        result.as_mut()[..context.rns_poly_len(level)]
            .as_chunks_mut::<N>()
            .0
            .iter_mut(),
    ) {
        for (out, value) in limb.iter_mut().zip(c0) {
            *out = u64::try_from(modulo(value, &IBig::from(q))).unwrap();
        }
        table.transform_slice(limb);
    }
    result
}

#[test]
fn restored_outputs_match_independent_wide_integer_algorithm_at_boundaries() {
    let context = context(T, &Q);
    let mut rng = StdRng::seed_from_u64(0x26_0aac);
    let client = BfvClient::generate(&context, &mut rng);
    for (external, working) in [(0, 0), (0, 1), (0, 2), (1, 1), (1, 2)] {
        let qs = &Q[..Q.len() - external];
        let q = total(qs);
        let ql = total(&Q[..Q.len() - working]);
        let d = &q / &ql;
        let half = &q / 2u64;
        let left = (0..N)
            .map(|i| match i % 6 {
                0 => half.clone(),
                1 => -&half,
                2 => &half - 1u64,
                3 => IBig::from(-1),
                4 => IBig::ZERO,
                _ => IBig::from(1),
            })
            .collect::<Vec<_>>();
        let right = (0..N)
            .map(|i| match i % 5 {
                0 => -&half,
                1 => &half - 2u64,
                2 => IBig::from(3),
                3 => IBig::from(-2),
                _ => IBig::ZERO,
            })
            .collect::<Vec<_>>();
        let key = client
            .relinearization_key(working, config(), &mut rng)
            .unwrap();
        for p_count in [1, 2] {
            let p = total(&P[..p_count]);
            let shrink = |xs: &[IBig]| {
                xs.iter()
                    .map(|x| center(&nearest(x, &d), &ql))
                    .collect::<Vec<_>>()
            };
            let a = shrink(&left);
            let b = shrink(&right);
            let scaled_b = b
                .iter()
                .map(|x| hps_scaled(x, &Q[..Q.len() - working], &p))
                .collect::<Vec<_>>();
            let expected = convolution(&a, &scaled_b)
                .into_iter()
                .map(|z| nearest(&(z * T), &p) * &d)
                .collect::<Vec<_>>();
            let left = c0_ciphertext(&context, external, &left);
            let right = c0_ciphertext(&context, external, &right);
            let mut actual = context.new_ciphertext(external);
            let mut request = BfvLeveledMultiplication::try_with_auxiliary_moduli(
                &context,
                external,
                &key,
                &P[..p_count],
            )
            .unwrap();
            request.multiply_to(&left, &right, &mut actual);
            assert_eq!(
                actual.as_ref(),
                c0_ciphertext(&context, external, &expected).as_ref(),
                "external {external}, working {working}, P limbs {p_count}"
            );
        }
    }
}

#[test]
fn real_radix_and_hybrid_chains_keep_external_geometry_and_recover_every_coefficient() {
    let context = context(T, &Q);
    let mut rng = StdRng::seed_from_u64(0x26_1eaf);
    let mut client = BfvClient::generate(&context, &mut rng);
    let a = Polynomial::new(
        (0..N)
            .map(|i| ((i as i64 % 5) - 2).rem_euclid(T as i64) as u64)
            .collect::<Vec<_>>(),
    );
    let b = Polynomial::new(
        (0..N)
            .map(|i| ((i as i64 % 3) - 1).rem_euclid(T as i64) as u64)
            .collect::<Vec<_>>(),
    );
    let expected_product = plaintext_product(a.as_ref(), b.as_ref());
    let expected_square = plaintext_product(a.as_ref(), a.as_ref());
    let expected_followup = plaintext_product(&expected_square, b.as_ref());
    let mut left = client.encrypt_centered(&a, &mut rng);
    let mut right = client.encrypt_centered(&b, &mut rng);
    for external in 0..2 {
        let ordinary_key = client
            .relinearization_key(external, config(), &mut rng)
            .unwrap();
        let mut ordinary = BfvMultiplication::try_with_backend(
            &context,
            &ordinary_key,
            BfvMultiplicationBackend::HpsPOverQ,
        )
        .unwrap();
        let mut output = context.new_ciphertext(external);
        for working in external..3 {
            for hybrid in [false, true] {
                let key = if hybrid {
                    let parameters = context
                        .hybrid_key_parameters(working, Q.len(), &P[..1])
                        .unwrap();
                    client
                        .relinearization_key(working, parameters, &mut rng)
                        .unwrap()
                } else {
                    client
                        .relinearization_key(working, config(), &mut rng)
                        .unwrap()
                };
                let mut request =
                    BfvLeveledMultiplication::try_new(&context, external, &key).unwrap();
                assert_eq!(request.external_level(), external);
                assert_eq!(request.working_level(), working);
                request.multiply_to(&left, &right, &mut output);
                assert_eq!(
                    client.decrypt_at_level(&output, external).as_ref(),
                    expected_product
                );
                let mut in_place = left.clone();
                request.square_to(&left, &mut output);
                request.square_assign(&mut in_place);
                assert_eq!(output.as_ref(), in_place.as_ref());
                assert_eq!(
                    client.decrypt_at_level(&output, external).as_ref(),
                    expected_square
                );
                // An ordinary request at the external level consumes the
                // restored output directly.
                ordinary.multiply_to(&output, &right, &mut in_place);
                assert_eq!(
                    client.decrypt_at_level(&in_place, external).as_ref(),
                    expected_followup
                );
            }
        }
        if external == 0 {
            let mut switch = BfvModulusSwitch::new(&context, 0);
            let mut next_left = context.new_ciphertext(1);
            let mut next_right = context.new_ciphertext(1);
            switch.switch_to(&left, &mut next_left);
            switch.switch_to(&right, &mut next_right);
            left = next_left;
            right = next_right;
        }
    }
    let key = client.relinearization_key(1, config(), &mut rng).unwrap();
    let mut request = BfvLeveledMultiplication::try_new(&context, 0, &key).unwrap();
    let mut values = vec![0; N];
    values[..2].copy_from_slice(&[1, 1]);
    let mut current = client.encrypt_centered(&Polynomial::new(values.clone()), &mut rng);
    for _ in 0..3 {
        request.square_assign(&mut current);
        values = plaintext_product(&values, &values);
        assert_eq!(client.decrypt_at_level(&current, 0).as_ref(), values);
        assert_eq!(current.as_ref().len(), 2 * context.rns_poly_len(0));
    }
}

#[test]
fn reversed_levels_wrong_keys_and_malformed_storage_fail_before_writes() {
    let context = context(T, &Q);
    let mut rng = StdRng::seed_from_u64(0x26_bad);
    let client = BfvClient::generate(&context, &mut rng);
    let full_key = client.relinearization_key(0, config(), &mut rng).unwrap();
    assert!(BfvLeveledMultiplication::try_new(&context, 1, &full_key).is_err());
    let key = client.relinearization_key(1, config(), &mut rng).unwrap();
    assert!(BfvLeveledMultiplication::try_new(&context, 3, &key).is_err());
    for wrong in [self::context(2, &Q), self::context(T, &[Q[1], Q[0], Q[2]])] {
        assert!(BfvLeveledMultiplication::try_new(&wrong, 0, &key).is_err());
    }
    for basis in [&[][..], &Q[..1], &[17][..], &[P[0], P[0]][..]] {
        assert!(
            BfvLeveledMultiplication::try_with_auxiliary_moduli(&context, 0, &key, basis).is_err()
        );
    }
    let mut request = BfvLeveledMultiplication::try_new(&context, 0, &key).unwrap();
    let valid = context.new_ciphertext(0);
    let length = valid.as_ref().len();
    for malformed_length in [0, length - 1, length + 1, 2 * length] {
        let mut malformed = BfvCiphertext::from_raw(vec![77; malformed_length]);
        let mut output = BfvCiphertext::from_raw(vec![55; length]);
        for (lhs, rhs) in [(&valid, &malformed), (&malformed, &valid)] {
            assert!(
                catch_unwind(AssertUnwindSafe(|| request.multiply_to(
                    lhs,
                    rhs,
                    &mut output
                )))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&x| x == 55));
        }
        assert!(
            catch_unwind(AssertUnwindSafe(
                || request.square_to(&malformed, &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 55));
        assert!(catch_unwind(AssertUnwindSafe(|| request.square_assign(&mut malformed))).is_err());
        assert!(malformed.as_ref().iter().all(|&x| x == 77));
        assert!(
            catch_unwind(AssertUnwindSafe(|| request.multiply_to(
                &valid,
                &valid,
                &mut malformed
            )))
            .is_err()
        );
        assert!(malformed.as_ref().iter().all(|&x| x == 77));
        assert!(
            catch_unwind(AssertUnwindSafe(
                || request.square_to(&valid, &mut malformed)
            ))
            .is_err()
        );
        assert!(malformed.as_ref().iter().all(|&x| x == 77));
    }
}
