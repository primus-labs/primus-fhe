//! General-prime history, independent quotient and checked representation contracts.
use primus_bgv::*;
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [1125899905351681, 1125899905744897, 1125899906629633];
fn context(n: usize, p: u64, qs: &[u64]) -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(n),
            BarrettModulus::new(p),
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
use primus_shape::PolyLength;
fn inverse(a: u64, p: u64) -> u64 {
    (1..p)
        .find(|&x| u128::from(a) * u128::from(x) % u128::from(p) == 1)
        .unwrap()
}
fn multiply(a: &[u64], b: &[u64], p: u64) -> Vec<u64> {
    let n = a.len();
    let mut out = vec![0_i128; n];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            out[(i + j) % n] += i128::from(a) * i128::from(b) * if i + j < n { 1 } else { -1 };
        }
    }
    out.into_iter()
        .map(|x| x.rem_euclid(i128::from(p)) as u64)
        .collect()
}
fn auto(a: &[u64], p: u64) -> Vec<u64> {
    let mut out = vec![0; a.len()];
    for (i, &x) in a.iter().enumerate() {
        let k = 5 * i;
        out[k % a.len()] = if (k / a.len()).is_multiple_of(2) {
            x
        } else {
            (p - x) % p
        };
    }
    out
}
fn key_config(context: &BgvContext, level: usize, hybrid: bool) -> BgvEvaluationKeyConfig {
    if hybrid {
        context
            .hybrid_key_parameters(
                level,
                context.base_q(level).moduli_count(),
                &[1152921504606584833],
            )
            .unwrap()
            .into()
    } else {
        context
            .radix_key_parameters(
                level,
                DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                },
            )
            .unwrap()
            .into()
    }
}

#[test]
fn distinct_histories_align_and_all_ordinary_consumers_preserve_the_factor() {
    let context = context(N, P, &Q);
    assert!(Q.iter().any(|q| q % P != 1));
    assert_ne!(Q[2] % P, 1);
    for hybrid in [false, true] {
        let mut rng = StdRng::seed_from_u64(2201);
        let mut alice = BgvClient::generate(&context, &mut rng);
        let mut bob = BgvClient::generate(&context, &mut rng);
        let pk = alice.public_key(&mut rng);
        let mut encryptor = context.public_key_encryptor(&pk).unwrap();
        let relin0 = alice
            .relinearization_key(0, key_config(&context, 0, hybrid), &mut rng)
            .unwrap();
        let relin1 = alice
            .relinearization_key(1, key_config(&context, 1, hybrid), &mut rng)
            .unwrap();
        let auto_key = alice
            .automorphism_key(1, 5, key_config(&context, 1, hybrid), &mut rng)
            .unwrap();
        let switch_key = bob
            .key_switching_key(&alice, 1, key_config(&context, 1, hybrid), &mut rng)
            .unwrap();
        let a = Polynomial::new(
            (0..N)
                .map(|i| (i as i64 % 7 - 3).rem_euclid(P as i64) as u64)
                .collect::<Vec<_>>(),
        );
        let mut b = context.new_plaintext();
        b.as_mut()[..4].copy_from_slice(&[3, P - 1, 2, 1]);
        let product = multiply(a.as_ref(), b.as_ref(), P);
        let ca = encryptor.encrypt_centered(&a, &mut rng);
        let cb = encryptor.encrypt_centered(&b, &mut rng);
        let mut ab = context.new_ciphertext(0);
        BgvMultiplication::try_new(&context, &relin0)
            .unwrap()
            .multiply_to(&ca, &cb, &mut ab);
        let mut drop0 = BgvModulusSwitch::new(&context, 0);
        let mut left = context.new_ciphertext(1);
        drop0.switch_to(&ab, &mut left);
        let mut da = context.new_ciphertext(1);
        let mut db = context.new_ciphertext(1);
        drop0.switch_to(&ca, &mut da);
        drop0.switch_to(&cb, &mut db);
        let mut right = context.new_ciphertext(1);
        let mut multiplication = BgvMultiplication::try_new(&context, &relin1).unwrap();
        multiplication.multiply_to(&da, &db, &mut right);
        let f = inverse(Q[2] % P, P);
        assert_eq!(left.correction_factor(), f);
        assert_eq!(right.correction_factor(), f * f % P);
        assert_ne!(left.correction_factor(), right.correction_factor());
        assert_eq!(alice.decrypt(&left).as_ref(), product);
        assert_eq!(alice.decrypt(&right).as_ref(), product);
        let mut evaluator = BgvEvaluator::new(&context, 1);
        let mut added = context.new_ciphertext(1);
        evaluator.add_to(&left.as_view(), &right, &mut added);
        let sum: Vec<_> = product.iter().map(|x| 2 * x % P).collect();
        assert_eq!(alice.decrypt(&added).as_ref(), sum);
        let mut in_place = left.clone();
        evaluator.add_assign(&mut in_place, &right);
        assert_eq!(in_place, added);
        let mut difference = context.new_ciphertext(1);
        evaluator.sub_to(&left, &right, &mut difference);
        assert!(alice.decrypt(&difference).as_ref().iter().all(|x| *x == 0));
        let mut in_place = left.clone();
        evaluator.sub_assign(&mut in_place, &right);
        assert_eq!(in_place, difference);
        let mut negated = context.new_ciphertext(1);
        evaluator.neg_to(&left, &mut negated);
        assert_eq!(negated.correction_factor(), f);
        assert_eq!(
            alice.decrypt(&negated).as_ref(),
            product.iter().map(|x| (P - x) % P).collect::<Vec<_>>()
        );
        let mut in_place = left.clone();
        evaluator.neg_assign(&mut in_place);
        assert_eq!(in_place, negated);
        let mut plain = context.new_plaintext();
        plain.as_mut()[0] = 5;
        plain.as_mut()[N - 1] = P - 2;
        let mut with_plain = context.new_ciphertext(1);
        evaluator.add_plain_to(&left, &plain, &mut with_plain, PlaintextEmbedding::Centered);
        assert_eq!(with_plain.correction_factor(), f);
        assert_eq!(
            alice.decrypt(&with_plain).as_ref(),
            product
                .iter()
                .zip(plain.as_ref())
                .map(|(x, y)| (x + y) % P)
                .collect::<Vec<_>>()
        );
        let mut in_place = left.clone();
        evaluator.add_plain_assign(&mut in_place, &plain, PlaintextEmbedding::Centered);
        assert_eq!(in_place, with_plain);
        evaluator.mul_plain_to(&left, &plain, &mut with_plain, PlaintextEmbedding::Unsigned);
        assert_eq!(with_plain.correction_factor(), f);
        assert_eq!(
            alice.decrypt(&with_plain).as_ref(),
            multiply(&product, plain.as_ref(), P)
        );
        let mut in_place = left.clone();
        evaluator.mul_plain_assign(&mut in_place, &plain, PlaintextEmbedding::Unsigned);
        assert_eq!(in_place, with_plain);
        let mut tensor = context.new_quadratic_ciphertext(1);
        evaluator.square_to(&left, &mut tensor);
        assert_eq!(tensor.correction_factor(), f * f % P);
        assert_eq!(tensor.as_view().correction_factor(), f * f % P);
        let mut squared = context.new_ciphertext(1);
        BgvRelinearizer::try_new(&context, &relin1)
            .unwrap()
            .relinearize_to(&tensor, &mut squared);
        assert_eq!(squared.correction_factor(), tensor.correction_factor());
        assert_eq!(
            alice.decrypt(&squared).as_ref(),
            multiply(&product, &product, P)
        );
        let mut permuted = context.new_ciphertext(1);
        BgvAutomorphism::try_new(&context, &auto_key)
            .unwrap()
            .apply_to(&left, &mut permuted);
        assert_eq!(permuted.correction_factor(), f);
        assert_eq!(alice.decrypt(&permuted).as_ref(), auto(&product, P));
        let mut switched = context.new_ciphertext(1);
        BgvKeySwitcher::try_new(&context, &switch_key)
            .unwrap()
            .switch_to(&left, &mut switched);
        assert_eq!(switched.correction_factor(), f);
        assert_eq!(bob.decrypt(&switched).as_ref(), product);
        let mut last = context.new_ciphertext(2);
        BgvModulusSwitch::new(&context, 1).switch_to(&switched, &mut last);
        assert_eq!(last.correction_factor(), f * inverse(Q[1] % P, P) % P);
        assert_eq!(bob.decrypt(&last).as_ref(), product);
        // Reusing an output from a different history cannot retain its old scale.
        let mut fresh = context
            .try_import_ciphertext(vec![0; 2 * context.rns_poly_len(0)], 0, 2)
            .unwrap();
        encryptor.encrypt_centered_to(&a, &mut fresh, &mut rng);
        assert_eq!(fresh.correction_factor(), 1);
        assert_eq!(alice.decrypt(&fresh), a);
        let mut fresh = context
            .try_import_ciphertext(vec![0; 2 * context.rns_poly_len(0)], 0, 2)
            .unwrap();
        alice.encrypt_to(&b, &mut fresh, &mut rng);
        assert_eq!(fresh.correction_factor(), 1);
        assert_eq!(alice.decrypt(&fresh), b);
    }
}

// Independent nearest-quotient-in-a-congruence-class oracle; it never forms
// the implementation's inverse-p centered remainder.
fn constrained_quotient(x: i128, q: u64, p: u64) -> i128 {
    let residue = (x * i128::from(inverse(q % p, p))).rem_euclid(i128::from(p));
    let k = (x - i128::from(q) * residue) / i128::from(p);
    residue + i128::from(p) * (k + i128::from(q / 2)).div_euclid(i128::from(q))
}

#[test]
fn general_drop_matches_independent_integer_quotients_and_recovers_composite_plaintext() {
    const QS: [u64; 3] = [257, 193, 449];
    const N: usize = 32;
    for p in [15, 17] {
        let context = context(N, p, &QS);
        let mut rng = StdRng::seed_from_u64(2202);
        let mut client = BgvClient::generate(&context, &mut rng);
        for factor in [1, 2, p - 1] {
            // A genuine zero-mask ciphertext with a known, bounded integer phase.
            let message = 3;
            let mut phase = i128::from(factor * message);
            let mut values = vec![0; 2 * context.rns_poly_len(0)];
            for (limb, &q) in values[..context.rns_poly_len(0)]
                .as_chunks_mut::<N>()
                .0
                .iter_mut()
                .zip(&QS)
            {
                limb[0] = phase.rem_euclid(i128::from(q)) as u64;
            }
            context
                .table()
                .transform_slice(&mut values[..context.rns_poly_len(0)]);
            let mut ciphertext = context.try_import_ciphertext(values, 0, factor).unwrap();
            assert_eq!(client.decrypt(&ciphertext).as_ref()[0], message);
            let mut f = factor;
            for (level, &q) in [QS[2], QS[1]].iter().enumerate() {
                let mut output = context.new_ciphertext(level + 1);
                BgvModulusSwitch::new(&context, level).switch_to(&ciphertext, &mut output);
                phase = constrained_quotient(phase, q, p);
                f = f * inverse(q % p, p) % p;
                assert_eq!(output.correction_factor(), f);
                for (limb, &qi) in output.as_ref()[..context.rns_poly_len(level + 1)]
                    .as_chunks::<N>()
                    .0
                    .iter()
                    .zip(&QS)
                {
                    assert!(
                        limb.iter()
                            .all(|x| *x == phase.rem_euclid(i128::from(qi)) as u64)
                    );
                }
                let recovered = client.decrypt(&output);
                assert_eq!(recovered.as_ref()[0], message);
                assert!(recovered.as_ref()[1..].iter().all(|x| *x == 0));
                ciphertext = output;
            }
        }
        for invalid in [0, p, p + 1] {
            assert!(matches!(
                context.try_import_ciphertext(vec![0; 2 * context.rns_poly_len(0)], 0, invalid),
                Err(BgvCiphertextBindingError::CorrectionFactor { .. })
            ));
        }
        if p == 15 {
            for invalid in [3, 5] {
                assert!(matches!(
                    context.try_import_ciphertext(vec![0; 2 * context.rns_poly_len(0)], 0, invalid),
                    Err(BgvCiphertextBindingError::CorrectionFactor { .. })
                ));
            }
        }
    }
}
