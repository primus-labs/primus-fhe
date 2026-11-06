//! Temporary key-basis switching: independent integer rounding and scaled embed.
use dashu_int::IBig;
use primus_bfv::{
    BfvAutomorphism, BfvCiphertext, BfvClient, BfvContext, BfvEvaluationKeyConfig,
    BfvEvaluationKeyError, BfvKeySwitcher, BfvMultiplier, BfvParameters, BfvQuadraticCiphertext,
    BfvRelinearizer,
};
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
const P: u64 = 257;
const Q: [u64; 4] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
    1_125_899_906_031_617,
];
fn context(q: &[u64]) -> BfvContext {
    BfvContext::try_with_levels(
        BfvParameters::try_with_error_distribution(
            PolyLength::new(N),
            BarrettModulus::new(P),
            BarrettModulus::new((1 << 61) - 1),
            &q.iter()
                .copied()
                .map(BarrettModulus::new)
                .collect::<Vec<_>>(),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        q.len(),
    )
    .unwrap()
}
fn config(c: &BfvContext, level: usize, hybrid: bool) -> BfvEvaluationKeyConfig {
    if hybrid {
        c.hybrid_key_parameters(level, Q.len(), &[1_152_921_504_606_584_833])
            .unwrap()
            .into()
    } else {
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: None,
        }
        .into()
    }
}
fn product(q: &[u64]) -> IBig {
    q.iter().fold(IBig::ONE, |x, &q| x * q)
}
fn modulo(x: IBig, q: &IBig) -> IBig {
    let r = x % q;
    if r < IBig::ZERO { r + q } else { r }
}
fn residue(x: &IBig, q: u64) -> u64 {
    u64::try_from(modulo(x.clone(), &IBig::from(q))).unwrap()
}
fn inverse(mut a: u64, mut e: u64, q: u64) -> u64 {
    let mut r = 1;
    while e != 0 {
        if e & 1 != 0 {
            r = (r as u128 * a as u128 % q as u128) as u64;
        }
        a = (a as u128 * a as u128 % q as u128) as u64;
        e >>= 1;
    }
    r
}
fn encode(c: &BfvContext, level: usize, polys: &[Vec<IBig>]) -> Vec<u64> {
    let qs = c.codec(level).moduli_values();
    let mut out = vec![0; polys.len() * N * qs.len()];
    for (poly, part) in polys.iter().zip(out.chunks_exact_mut(N * qs.len())) {
        for ((&q, table), limb) in qs
            .iter()
            .zip(c.table().iter())
            .zip(part.as_chunks_mut::<N>().0.iter_mut())
        {
            for (out, x) in limb.iter_mut().zip(poly) {
                *out = residue(x, q);
            }
            table.transform_slice(limb);
        }
    }
    out
}
fn decode(c: &BfvContext, level: usize, words: &[u64]) -> Vec<Vec<IBig>> {
    let qs = c.codec(level).moduli_values();
    let q = product(qs);
    let half = &q / 2u8;
    let hats = qs
        .iter()
        .map(|&prime| {
            let h = &q / prime;
            let inv = inverse(residue(&h, prime), prime - 2, prime);
            h * inv
        })
        .collect::<Vec<_>>();
    words
        .chunks_exact(N * qs.len())
        .map(|part| {
            let mut coeff = part.to_vec();
            for (table, limb) in c
                .table()
                .iter()
                .zip(coeff.as_chunks_mut::<N>().0.iter_mut())
            {
                table.inverse_transform_slice(limb);
            }
            (0..N)
                .map(|i| {
                    let sum = hats
                        .iter()
                        .enumerate()
                        .fold(IBig::ZERO, |sum, (j, h)| sum + h * coeff[j * N + i]);
                    let x = modulo(sum, &q);
                    if x > half { x - &q } else { x }
                })
                .collect()
        })
        .collect()
}
fn round(x: &IBig, d: &IBig) -> IBig {
    let a = x + d / 2u8;
    (&a - modulo(a.clone(), d)) / d
}
fn permutation(input: &[IBig]) -> Vec<IBig> {
    let mut out = vec![IBig::ZERO; N];
    for (i, x) in input.iter().enumerate() {
        let index = (i * 5) % (2 * N);
        out[index % N] = if index < N { x.clone() } else { -x };
    }
    out
}

#[test]
fn all_temporary_prefixes_match_independent_simultaneous_round_and_scaled_embedding() {
    let c = context(&Q);
    let mut rng = StdRng::seed_from_u64(0x26_ba515);
    let source = BfvClient::generate(&c, &mut rng);
    let target = BfvClient::generate(&c, &mut rng);
    for hybrid in [false, true] {
        for external in 0..Q.len() {
            for working in external..Q.len() {
                let qs = &Q[..Q.len() - external];
                let q = product(qs);
                let d = product(&qs[Q.len() - working..]);
                let half = &d / 2u8;
                let polys = (0..3)
                    .map(|component| {
                        (0..N)
                            .map(|i| {
                                let x = match i % 8 {
                                    0 => IBig::ZERO,
                                    1 => half.clone(),
                                    2 => &half + 1u8,
                                    3 => -&half,
                                    4 => -&half - 1u8,
                                    5 => &q / 2u8,
                                    6 => -&q / 2u8,
                                    _ => IBig::from((i + component) as u64) * &d + &half,
                                };
                                if component == 2 {
                                    x
                                } else {
                                    x + (component * 13 + i) as u64
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let full = encode(&c, external, &polys);
                let l = N * qs.len();
                let ct = BfvCiphertext::from_raw(full[..2 * l].to_vec());
                let low1 = polys[1].iter().map(|x| round(x, &d)).collect::<Vec<_>>();
                let low2 = polys[2].iter().map(|x| round(x, &d)).collect::<Vec<_>>();
                let zeros = vec![IBig::ZERO; N];
                let lower = BfvCiphertext::from_raw(encode(&c, working, &[zeros.clone(), low1]));
                let quadratic = BfvQuadraticCiphertext::from_raw(full.clone());
                let low_quad = BfvQuadraticCiphertext::from_raw(encode(
                    &c,
                    working,
                    &[zeros.clone(), zeros, low2],
                ));
                let sk = target
                    .key_switching_key(&source, working, config(&c, working, hybrid), &mut rng)
                    .unwrap();
                let rk = source
                    .relinearization_key(working, config(&c, working, hybrid), &mut rng)
                    .unwrap();
                let ak = source
                    .automorphism_key(working, 5, config(&c, working, hybrid), &mut rng)
                    .unwrap();
                let mut switch = BfvKeySwitcher::try_with_working_level(&c, external, &sk).unwrap();
                let mut relin = BfvRelinearizer::try_with_working_level(&c, external, &rk).unwrap();
                let mut auto = BfvAutomorphism::try_with_working_level(&c, external, &ak).unwrap();
                let mut output = c.new_ciphertext(external);
                let mut low_output = c.new_ciphertext(working);
                for kind in 0..3 {
                    match kind {
                        0 => {
                            BfvKeySwitcher::try_new(&c, &sk)
                                .unwrap()
                                .switch_to(&lower, &mut low_output);
                            switch.switch_to(&ct, &mut output);
                        }
                        1 => {
                            BfvRelinearizer::try_new(&c, &rk)
                                .unwrap()
                                .relinearize_to(&low_quad, &mut low_output);
                            relin.relinearize_to(&quadratic, &mut output);
                        }
                        _ => {
                            BfvAutomorphism::try_new(&c, &ak)
                                .unwrap()
                                .apply_to(&lower, &mut low_output);
                            auto.apply_to(&ct, &mut output);
                        }
                    }
                    let mut expected = decode(&c, working, low_output.as_ref());
                    for poly in &mut expected {
                        for x in poly {
                            *x *= &d;
                        }
                    }
                    let original0 = if kind == 2 {
                        permutation(&polys[0])
                    } else {
                        polys[0].clone()
                    };
                    for (out, x) in expected[0].iter_mut().zip(original0) {
                        *out += x;
                    }
                    if kind == 1 {
                        for (out, x) in expected[1].iter_mut().zip(&polys[1]) {
                            *out += x;
                        }
                    }
                    assert_eq!(
                        output.as_ref(),
                        encode(&c, external, &expected),
                        "hybrid={hybrid} external={external} working={working} role={kind}"
                    );
                }
            }
        }
    }
}

#[test]
fn working_keys_preserve_real_messages_and_reject_levels_or_storage_before_writes() {
    let c = context(&Q);
    let mut rng = StdRng::seed_from_u64(0x265e_c0e7);
    let mut source = BfvClient::generate(&c, &mut rng);
    let mut target = BfvClient::generate(&c, &mut rng);
    let m = Polynomial::new((0..N).map(|i| (i as u64 * 3 + 1) % P).collect::<Vec<_>>());
    let ciphertext = source.encrypt_centered(&m, &mut rng);
    let mut square = c.new_quadratic_ciphertext(0);
    BfvMultiplier::try_with_default_basis(&c, 0)
        .unwrap()
        .square_to(&ciphertext, &mut square);
    let mut expected_square = vec![IBig::ZERO; N];
    for (i, &a) in m.as_ref().iter().enumerate() {
        for (j, &b) in m.as_ref().iter().enumerate() {
            let product = IBig::from(a) * b;
            if i + j < N {
                expected_square[i + j] += product;
            } else {
                expected_square[i + j - N] -= product;
            }
        }
    }
    let expected_square = expected_square
        .iter()
        .map(|x| residue(x, P))
        .collect::<Vec<_>>();
    for hybrid in [false, true] {
        for working in 0..Q.len() {
            let sk = target
                .key_switching_key(&source, working, config(&c, working, hybrid), &mut rng)
                .unwrap();
            let ak = source
                .automorphism_key(working, 5, config(&c, working, hybrid), &mut rng)
                .unwrap();
            let rk = source
                .relinearization_key(working, config(&c, working, hybrid), &mut rng)
                .unwrap();
            let mut switch = BfvKeySwitcher::try_with_working_level(&c, 0, &sk).unwrap();
            let mut auto = BfvAutomorphism::try_with_working_level(&c, 0, &ak).unwrap();
            let mut relin = BfvRelinearizer::try_with_working_level(&c, 0, &rk).unwrap();
            let mut output = c.new_ciphertext(0);
            switch.switch_to(&ciphertext, &mut output);
            assert_eq!(target.decrypt_at_level(&output, 0).as_ref(), m.as_ref());
            auto.apply_to(&ciphertext, &mut output);
            let want = permutation(
                &m.as_ref()
                    .iter()
                    .map(|&x| IBig::from(x))
                    .collect::<Vec<_>>(),
            )
            .iter()
            .map(|x| residue(x, P))
            .collect::<Vec<_>>();
            assert_eq!(source.decrypt_at_level(&output, 0).as_ref(), want);
            relin.relinearize_to(&square, &mut output);
            assert_eq!(
                source.decrypt_at_level(&output, 0).as_ref(),
                expected_square
            );
            assert!(matches!(
                BfvKeySwitcher::try_with_working_level(&c, Q.len(), &sk),
                Err(BfvEvaluationKeyError::Level { .. })
            ));
            if working > 0 {
                let full = source
                    .relinearization_key(0, config(&c, 0, hybrid), &mut rng)
                    .unwrap();
                assert!(matches!(
                    BfvRelinearizer::try_with_working_level(&c, working, &full),
                    Err(BfvEvaluationKeyError::WorkingLevel { .. })
                ));
            }
            let length = 2 * c.rns_poly_len(0);
            let bad = BfvCiphertext::from_raw(vec![0; length - 1]);
            let quad = BfvQuadraticCiphertext::zero_raw(length / 2 * 3 - 1);
            for role in 0..3 {
                let mut sentinel = BfvCiphertext::from_raw(vec![31; length]);
                assert!(
                    catch_unwind(AssertUnwindSafe(|| match role {
                        0 => switch.switch_to(&bad, &mut sentinel),
                        1 => auto.apply_to(&bad, &mut sentinel),
                        _ => relin.relinearize_to(&quad, &mut sentinel),
                    }))
                    .is_err()
                );
                assert!(sentinel.as_ref().iter().all(|&x| x == 31));
                let mut bad_output = BfvCiphertext::from_raw(vec![37; length - 1]);
                assert!(
                    catch_unwind(AssertUnwindSafe(|| match role {
                        0 => switch.switch_to(&ciphertext, &mut bad_output),
                        1 => auto.apply_to(&ciphertext, &mut bad_output),
                        _ => relin.relinearize_to(&square, &mut bad_output),
                    }))
                    .is_err()
                );
                assert!(bad_output.as_ref().iter().all(|&x| x == 37));
            }
        }
    }
}
