//! Compare sequential and two-worker expansion on the same keys and ciphertexts.
//! N=32 retains a multi-level tree; two ~50-bit limbs retain wide CRT arithmetic.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffParallelEvaluator,
    DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey,
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

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = support::RawParameters::new(
        GlweDimension::new(dimension),
        poly_length,
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

    let glev_params = glwe_params.gadget(DecompositionBaseLog::new(20), None);
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
    let mut transformed = DcrtGlweCiphertext::<Vec<ValueT>>::zero(rns_glwe_len);

    let raw_domain = glwe_params.domain(&table);
    let dcrt_sk_context = dcrt_sk.try_bind_raw(&raw_domain).unwrap();
    let bound = support::tree_error_bound(&glev_params);
    dcrt_sk_context.encrypt_encoded_crt_to(
        &support::unsigned_probe(input1.as_ref(), &glwe_params),
        &mut c1,
        &mut rng,
    );

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

    // Each output phase approximates (m_i, 0, …, 0)
    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        cipher.write_ntt_form(&mut transformed, &table);
        support::assert_scalar_probe(&dcrt_sk, &glwe_params, &table, &transformed, input, bound);
    }

    // Wraps back to DCRT domain, zeros out high coefficients, re-encrypts.
    let mut c1 = DcrtGlweCiphertext::new(c1.0);

    // This case has zero omitted coefficients; the nonzero-tail case is below. Reuse dirty
    // output buffers and both workspaces from the full expansion.
    for retained in [n / 2, 1] {
        input1[retained..].fill(0);

        dcrt_sk_context.encrypt_encoded_crt_to(
            &support::unsigned_probe(input1.as_ref(), &glwe_params),
            &mut c1,
            &mut rng,
        );

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
            support::assert_scalar_probe(
                &dcrt_sk,
                &glwe_params,
                &table,
                &transformed,
                input,
                bound,
            );
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

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = support::RawParameters::new(
        GlweDimension::new(dimension),
        poly_length,
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

    let glev_params = glwe_params.gadget(DecompositionBaseLog::new(20), None);
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

    let raw_domain = glwe_params.domain(&table);
    let dcrt_sk_context = dcrt_sk.try_bind_raw(&raw_domain).unwrap();
    let bound = support::tree_error_bound(&glev_params);
    dcrt_sk_context.encrypt_encoded_crt_to(
        &support::unsigned_probe(input1.as_ref(), &glwe_params),
        &mut c1,
        &mut rng,
    );

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

    // Results are already in NTT domain; inspect their raw phase.
    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        support::assert_scalar_probe(&dcrt_sk, &glwe_params, &table, cipher, input, bound);
    }

    // This case has zero omitted coefficients; the nonzero-tail case is below. Reuse dirty
    // output buffers and both workspaces from the full expansion.
    for retained in [n / 2, 1] {
        input1[retained..].fill(0);

        dcrt_sk_context.encrypt_encoded_crt_to(
            &support::unsigned_probe(input1.as_ref(), &glwe_params),
            &mut c1,
            &mut rng,
        );

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
            support::assert_scalar_probe(&dcrt_sk, &glwe_params, &table, cipher, input, bound);
        }
    }
}

// Count actual transform work to detect padded automorphism evaluation. This
// test-only adapter delegates numerical transforms unchanged to the optimized
// table; each limb has an independent counter, so tests need no global state.
struct CountingNtt {
    table: primus_ntt::U64NttTable,
    calls: std::sync::atomic::AtomicUsize,
}

impl primus_ntt::NttTable for CountingNtt {
    type ValueT = u64;

    fn new<M: primus_reduce::FieldContext<u64>>(
        n: PolyLength,
        modulus: M,
    ) -> Result<Self, primus_ntt::NttError<u64>> {
        Ok(Self {
            table: primus_ntt::U64NttTable::new(n, modulus)?,
            calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn poly_length(&self) -> PolyLength {
        self.table.poly_length()
    }
    fn modulus(&self) -> u64 {
        self.table.modulus()
    }
    fn transform_slice(&self, values: &mut [u64]) {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.table.transform_slice(values);
    }
    fn inverse_transform_slice(&self, values: &mut [u64]) {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.table.inverse_transform_slice(values);
    }
    fn lazy_transform_slice(&self, values: &mut [u64]) {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.table.lazy_transform_slice(values);
    }
    fn lazy_inverse_transform_slice(&self, values: &mut [u64]) {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.table.lazy_inverse_transform_slice(values);
    }
}

impl primus_ntt::MonomialNttTable for CountingNtt {
    fn root_powers(&self) -> &[u64] {
        self.table.root_powers()
    }
    fn inv_root_powers(&self) -> &[u64] {
        self.table.inv_root_powers()
    }
}

#[test]
fn supported_prefixes_prune_work_and_preserve_block_expansion() {
    use primus_ntt::DcrtTable;
    use std::sync::atomic::Ordering;

    let n = PolyLength::new(32);
    let moduli = [1125899906826241u64, 1125899906629633].map(BarrettModulus::new);
    let parameters = support::RawParameters::new(
        GlweDimension::new(2),
        n,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let table = DcrtTable::<CountingNtt>::new(n, &moduli).unwrap();
    let work = || {
        table
            .iter()
            .map(|limb| limb.calls.swap(0, Ordering::Relaxed))
            .sum::<usize>()
    };
    let mut rng = StdRng::seed_from_u64(0x5052_4546_4958);
    let secret = GlweSecretKey::generate(
        parameters.glwe_size(),
        parameters.secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let raw_domain = parameters.domain(&table);
    let context = key.try_bind_raw(&raw_domain).unwrap();
    let gadget = parameters.gadget(DecompositionBaseLog::new(20), None);
    let bound = support::tree_error_bound(&gadget);
    let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let dcrt_key = DcrtGlweExpandCoeffKey::new(&domain, &key, &mut rng);
    let crt_key = CrtGlweExpandCoeffKey::new(&domain, &secret, &key, &mut rng);
    let mut serial = DcrtGlweExpandCoeffEvaluator::new(&dcrt_key, &domain);
    let mut parallel_one = DcrtGlweExpandCoeffParallelEvaluator::new(&dcrt_key, &domain, 1);
    let mut parallel_two = DcrtGlweExpandCoeffParallelEvaluator::new(&dcrt_key, &domain, 2);
    let mut crt_serial = CrtGlweExpandCoeffEvaluator::new(&crt_key, &domain);
    let mut crt_parallel = CrtGlweExpandCoeffParallelEvaluator::new(&crt_key, &domain, 1);
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    let length = parameters.rns_glwe_len();
    let mut ciphertext = DcrtGlweCiphertext::<Vec<u64>>::zero(length);
    let mut transformed = DcrtGlweCiphertext::<Vec<u64>>::zero(length);
    let mut one_auto_work = None;
    let mut one_crt_auto_work = None;

    // Every support size, including 1/3/5/N-1/N; every output has a distinct
    // known coefficient. The oracle reads the original message, never a decoded
    // intermediate or another expansion implementation.
    for count in 1..=n.get() {
        let mut message = Polynomial::<Vec<u64>>::zero(n.get());
        for (index, coefficient) in message[..count].iter_mut().enumerate() {
            *coefficient = (17 * index + 3) as u64;
        }
        context.encrypt_encoded_crt_to(
            &support::unsigned_probe(message.as_ref(), &parameters),
            &mut ciphertext,
            &mut rng,
        );
        let crt_input = ciphertext.clone().into_coeff_form(&table);
        let mut output = vec![DcrtGlweCiphertext::new(vec![1u64; length]); count];
        let mut other = output.clone();
        work();
        serial.expand_supported_coefficients_to(&ciphertext, &mut output);
        let actual_work = work();
        if count == 1 {
            assert_eq!(actual_work, 0);
        }
        if count == 2 {
            assert!(actual_work > 0);
            one_auto_work = Some(actual_work);
        }
        if let Some(unit) = one_auto_work {
            assert_eq!(actual_work, (count - 1) * unit);
        }
        for parallel in [&mut parallel_one, &mut parallel_two] {
            workers.install(|| parallel.expand_supported_coefficients_to(&ciphertext, &mut other));
            for (expected, actual) in output.iter().zip(&other) {
                assert_eq!(expected.as_ref(), actual.as_ref());
            }
        }
        for (index, leaf) in output.iter().enumerate() {
            support::assert_scalar_probe(&key, &parameters, &table, leaf, message[index], bound);
        }
        let mut crt_output = vec![CrtGlwe::new(vec![1u64; length]); count];
        let mut crt_other = crt_output.clone();
        work();
        crt_serial.expand_supported_coefficients_to(&crt_input, &mut crt_output);
        let actual_work = work();
        if count == 1 {
            assert_eq!(actual_work, 0);
        }
        if count == 2 {
            assert!(actual_work > 0);
            one_crt_auto_work = Some(actual_work);
        }
        if let Some(unit) = one_crt_auto_work {
            assert_eq!(actual_work, (count - 1) * unit);
        }
        workers
            .install(|| crt_parallel.expand_supported_coefficients_to(&crt_input, &mut crt_other));
        for (index, (leaf, parallel)) in crt_output.iter().zip(&crt_other).enumerate() {
            assert_eq!(leaf.as_ref(), parallel.as_ref());
            leaf.write_ntt_form(&mut transformed, &table);
            support::assert_scalar_probe(
                &key,
                &parameters,
                &table,
                &transformed,
                message[index],
                bound,
            );
        }
    }

    // A nonzero high tail is legal for power-of-two partial expansion. Its
    // independent residue-class oracle keeps m[j+k*d] at X^(k*d), not a scalar.
    let message = Polynomial::new(
        (0..n.get())
            .map(|index| (index + 1) as u64)
            .collect::<Vec<_>>(),
    );
    context.encrypt_encoded_crt_to(
        &support::unsigned_probe(message.as_ref(), &parameters),
        &mut ciphertext,
        &mut rng,
    );
    let crt_input = ciphertext.clone().into_coeff_form(&table);
    for count in [1, 2, 4, 8, 16] {
        let mut output = vec![DcrtGlweCiphertext::<Vec<u64>>::zero(length); count];
        let mut crt_output = vec![CrtGlwe::<Vec<u64>>::zero(length); count];
        serial.expand_partial_coefficients_to(&ciphertext, &mut output);
        crt_serial.expand_partial_coefficients_to(&crt_input, &mut crt_output);
        for index in 0..count {
            let mut expected = vec![0; n.get()];
            for source in (index..n.get()).step_by(count) {
                expected[source - index] = message[source];
            }
            support::assert_probe_phase(
                &key,
                &parameters,
                &table,
                &output[index],
                &expected
                    .iter()
                    .map(|&value| i128::from(value))
                    .collect::<Vec<_>>(),
                bound,
            );
            crt_output[index].write_ntt_form(&mut transformed, &table);
            support::assert_probe_phase(
                &key,
                &parameters,
                &table,
                &transformed,
                &expected
                    .iter()
                    .map(|&value| i128::from(value))
                    .collect::<Vec<_>>(),
                bound,
            );
        }
    }

    // All batch shapes are validated before any output is normalized, including
    // an invalid later leaf that a truncating zip could otherwise skip.
    for count in [0, n.get() + 1] {
        let mut output = vec![DcrtGlweCiphertext::new(vec![1u64; length]); count];
        assert!(
            catch_unwind(AssertUnwindSafe(
                || serial.expand_supported_coefficients_to(&ciphertext, &mut output)
            ))
            .is_err()
        );
        assert!(
            output
                .iter()
                .all(|leaf| leaf.as_ref().iter().all(|&x| x == 1))
        );
    }
    let mut output = vec![DcrtGlweCiphertext::new(vec![1u64; length]); 3];
    output[1] = DcrtGlweCiphertext::new(vec![1u64; length - 1]);
    for parallel in [false, true] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if parallel {
                    workers.install(|| {
                        parallel_one.expand_supported_coefficients_to(&ciphertext, &mut output)
                    });
                } else {
                    serial.expand_supported_coefficients_to(&ciphertext, &mut output);
                }
            }))
            .is_err()
        );
        assert!(
            output
                .iter()
                .all(|leaf| leaf.as_ref().iter().all(|&x| x == 1))
        );
    }
    let mut valid_output = vec![DcrtGlweCiphertext::new(vec![1u64; length]); 3];
    let short_input = DcrtGlweCiphertext::new(&ciphertext.as_ref()[..length - 1]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            serial.expand_supported_coefficients_to(&short_input, &mut valid_output);
        }))
        .is_err()
    );
    assert!(
        valid_output
            .iter()
            .all(|leaf| leaf.as_ref().iter().all(|&x| x == 1))
    );
    let mut crt_output = vec![CrtGlwe::new(vec![1u64; length]); 3];
    crt_output[2] = CrtGlwe::new(vec![1u64; length + 1]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            crt_serial.expand_supported_coefficients_to(&crt_input, &mut crt_output);
        }))
        .is_err()
    );
    assert!(
        crt_output
            .iter()
            .all(|leaf| leaf.as_ref().iter().all(|&x| x == 1))
    );
}
