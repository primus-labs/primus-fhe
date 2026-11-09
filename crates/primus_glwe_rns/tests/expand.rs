//! Compare sequential and two-worker expansion on the same keys and ciphertexts.
//! N=32 retains a multi-level tree; two ~50-bit limbs retain wide CRT arithmetic.
use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffKey,
    CrtGlweExpandCoeffParallelEvaluator, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweDecryptWorkspace, DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey,
    DcrtGlweExpandCoeffParallelEvaluator, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::glwe::CrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Test coefficient expansion in the coefficient (CRT) domain.
///
/// Expands a GLWE ciphertext encrypting m(X) into N ciphertexts,
/// one per coefficient: the i-th output encrypts m_i (the i-th coefficient).
/// Verifies full expansion and partial expansion with N/2 and one output.
#[test]
fn crt_expansion_matches_parallel_and_plaintext() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length = PolyLength::new(32);
    let n = poly_length.get();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let expand_key = CrtGlweExpandCoeffKey::new(&domain, &sk, &dcrt_sk, &mut rng);

    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(n, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<CrtGlwe<Vec<ValueT>>> = vec![CrtGlwe::zero(rns_glwe_len); n];
    let mut evaluator = CrtGlweExpandCoeffEvaluator::new(&expand_key, &domain);
    let mut parallel_evaluator = CrtGlweExpandCoeffParallelEvaluator::new(&expand_key, &domain, 2);
    let mut parallel_output = c_expand.clone();
    // Use a local pool so this small correctness test does not create a worker
    // per CI core. Parallel evaluations reuse the two preallocated workspaces.
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());
    let mut transformed = DcrtGlweCiphertext::<Vec<ValueT>>::zero(rns_glwe_len);

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

    // Requires conversion to coefficient domain first.
    let c1 = c1.into_coeff_form(&table);

    // Full expansion rejects even a valid partial count; partial expansion
    // rejects zero, non-powers of two and powers of two above N.
    // Dirty sentinels must survive every rejection before either kernel writes.
    for full in [true, false] {
        let invalid_counts = if full {
            [0, n / 2, n + 1]
        } else {
            [0, 3, 2 * n]
        };
        for count in invalid_counts {
            let mut rejected = vec![CrtGlwe::new(vec![1; rns_glwe_len]); count];
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if full {
                        evaluator.expand_coefficients_to(&c1, &mut rejected);
                    } else {
                        evaluator.expand_partial_coefficients_to(&c1, &mut rejected);
                    }
                }))
                .is_err()
            );
            assert!(
                rejected
                    .iter()
                    .all(|cipher| cipher.as_ref().iter().all(|&v| v == 1))
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if full {
                        parallel_evaluator.expand_coefficients_to(&c1, &mut rejected);
                    } else {
                        parallel_evaluator.expand_partial_coefficients_to(&c1, &mut rejected);
                    }
                }))
                .is_err()
            );
            assert!(
                rejected
                    .iter()
                    .all(|cipher| cipher.as_ref().iter().all(|&v| v == 1))
            );
        }
    }

    evaluator.expand_coefficients_to(&c1, &mut c_expand);
    workers.install(|| {
        parallel_evaluator.expand_coefficients_to(&c1, &mut parallel_output);
    });
    for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
        assert_eq!(sequential.as_ref(), parallel.as_ref());
    }

    // N is also a valid partial count. Both entry points must use the same
    // normalization and overwrite dirty outputs with identical ciphertexts.
    let full_output = c_expand.clone();
    evaluator.expand_partial_coefficients_to(&c1, &mut c_expand);
    workers.install(|| {
        parallel_evaluator.expand_partial_coefficients_to(&c1, &mut parallel_output);
    });
    for ((sequential, parallel), full) in c_expand.iter().zip(&parallel_output).zip(&full_output) {
        assert_eq!(sequential.as_ref(), full.as_ref());
        assert_eq!(parallel.as_ref(), full.as_ref());
    }

    // Each output decrypts to (m_i, 0, …, 0)
    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        cipher.write_ntt_form(&mut transformed, &table);
        let m_dec = dcrt_sk_context.decrypt(&transformed, &mut decrypt_workspace);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // Wraps back to DCRT domain, zeros out high coefficients, re-encrypts.
    let mut c1 = DcrtGlweCiphertext::new(c1.0);

    // Partial expansion assumes the omitted coefficients are zero. Reuse dirty
    // output buffers and both workspaces from the full expansion.
    for retained in [n / 2, 1] {
        input1[retained..].fill(0);

        dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

        let crt_input = c1.clone().into_coeff_form(&table);

        c_expand.truncate(retained);
        parallel_output.truncate(retained);

        evaluator.expand_partial_coefficients_to(&crt_input, &mut c_expand);
        workers.install(|| {
            parallel_evaluator.expand_partial_coefficients_to(&crt_input, &mut parallel_output);
        });
        for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
            assert_eq!(sequential.as_ref(), parallel.as_ref());
        }

        for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
            cipher.write_ntt_form(&mut transformed, &table);
            let m_dec = dcrt_sk_context.decrypt(&transformed, &mut decrypt_workspace);
            assert_eq!(input, m_dec[0]);
            assert!(m_dec[1..].iter().all(|&v| v == 0));
        }
    }
}

/// Test coefficient expansion in the NTT (DCRT) domain.
///
/// Same as [`crt_expansion_matches_parallel_and_plaintext`] but the ciphertext stays
/// in the NTT domain — no conversion to coefficient form required.
#[test]
fn dcrt_expansion_matches_parallel_and_plaintext() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length = PolyLength::new(32);
    let n = poly_length.get();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let expand_key = DcrtGlweExpandCoeffKey::new(&domain, &dcrt_sk, &mut rng);

    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(n, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<DcrtGlweCiphertext<Vec<ValueT>>> =
        vec![DcrtGlweCiphertext::zero(rns_glwe_len); n];
    let mut evaluator = DcrtGlweExpandCoeffEvaluator::new(&expand_key, &domain);
    let mut parallel_evaluator = DcrtGlweExpandCoeffParallelEvaluator::new(&expand_key, &domain, 2);
    let mut parallel_output = c_expand.clone();
    // Use a local pool so this small correctness test does not create a worker
    // per CI core. Parallel evaluations reuse the two preallocated workspaces.
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

    // Full expansion rejects even a valid partial count; partial expansion
    // rejects zero, non-powers of two and powers of two above N.
    // Dirty sentinels must survive every rejection before either kernel writes.
    for full in [true, false] {
        let invalid_counts = if full {
            [0, n / 2, n + 1]
        } else {
            [0, 3, 2 * n]
        };
        for count in invalid_counts {
            let mut rejected = vec![DcrtGlweCiphertext::new(vec![1; rns_glwe_len]); count];
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if full {
                        evaluator.expand_coefficients_to(&c1, &mut rejected);
                    } else {
                        evaluator.expand_partial_coefficients_to(&c1, &mut rejected);
                    }
                }))
                .is_err()
            );
            assert!(
                rejected
                    .iter()
                    .all(|cipher| cipher.as_ref().iter().all(|&v| v == 1))
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if full {
                        parallel_evaluator.expand_coefficients_to(&c1, &mut rejected);
                    } else {
                        parallel_evaluator.expand_partial_coefficients_to(&c1, &mut rejected);
                    }
                }))
                .is_err()
            );
            assert!(
                rejected
                    .iter()
                    .all(|cipher| cipher.as_ref().iter().all(|&v| v == 1))
            );
        }
    }

    evaluator.expand_coefficients_to(&c1, &mut c_expand);
    workers.install(|| {
        parallel_evaluator.expand_coefficients_to(&c1, &mut parallel_output);
    });
    for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
        assert_eq!(sequential.as_ref(), parallel.as_ref());
    }

    // N is also a valid partial count. Both entry points must use the same
    // normalization and overwrite dirty outputs with identical ciphertexts.
    let full_output = c_expand.clone();
    evaluator.expand_partial_coefficients_to(&c1, &mut c_expand);
    workers.install(|| {
        parallel_evaluator.expand_partial_coefficients_to(&c1, &mut parallel_output);
    });
    for ((sequential, parallel), full) in c_expand.iter().zip(&parallel_output).zip(&full_output) {
        assert_eq!(sequential.as_ref(), full.as_ref());
        assert_eq!(parallel.as_ref(), full.as_ref());
    }

    // Results are already in NTT domain — decrypt directly.
    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        let m_dec = dcrt_sk_context.decrypt(cipher, &mut decrypt_workspace);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // Partial expansion assumes the omitted coefficients are zero. Reuse dirty
    // output buffers and both workspaces from the full expansion.
    for retained in [n / 2, 1] {
        input1[retained..].fill(0);

        dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

        c_expand.truncate(retained);
        parallel_output.truncate(retained);

        evaluator.expand_partial_coefficients_to(&c1, &mut c_expand);
        workers.install(|| {
            parallel_evaluator.expand_partial_coefficients_to(&c1, &mut parallel_output);
        });
        for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
            assert_eq!(sequential.as_ref(), parallel.as_ref());
        }

        for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
            let m_dec = dcrt_sk_context.decrypt(cipher, &mut decrypt_workspace);
            assert_eq!(input, m_dec[0]);
            assert!(m_dec[1..].iter().all(|&v| v == 0));
        }
    }
}
