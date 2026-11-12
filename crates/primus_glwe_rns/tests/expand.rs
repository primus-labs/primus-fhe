//! Compare sequential and two-worker expansion on the same keys and ciphertexts.
//! N=32 retains a multi-level tree; two ~50-bit limbs retain wide CRT arithmetic.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffParallelEvaluator,
    DcrtGlweCiphertext, DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey,
    DcrtGlweExpandCoeffParallelEvaluator, DcrtGlweSecretKey, GlweSecretKey,
};
use primus_lattice::glwe::CrtGlwe;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn assert_rejected_outputs<C: AsRef<[u64]>>(output: &mut [C], expand: impl FnOnce(&mut [C])) {
    assert!(catch_unwind(AssertUnwindSafe(|| expand(output))).is_err());
    assert!(
        output
            .iter()
            .all(|cipher| cipher.as_ref().iter().all(|&v| v == 1))
    );
}

fn check_expansion_counts<C: AsRef<[u64]>>(
    n: usize,
    leaf: impl Fn() -> C,
    mut serial: impl FnMut(bool, &mut [C]),
    mut parallel: impl FnMut(bool, &mut [C]),
) {
    // Full rejects a valid partial count. Partial rejects empty, irregular
    // and oversized counts. The parallel entry points each get a witness.
    for (full, count) in [
        (true, n / 2),
        (true, n + 1),
        (false, 0),
        (false, 3),
        (false, 2 * n),
    ] {
        let mut output: Vec<_> = (0..count).map(|_| leaf()).collect();
        assert_rejected_outputs(&mut output, |output| serial(full, output));
        if count == n / 2 || count == 3 {
            assert_rejected_outputs(&mut output, |output| parallel(full, output));
        }
    }
}

#[test]
fn crt_and_dcrt_full_and_partial_expansion_match_parallel_and_plaintext() {
    let parameters = support::probe_parameters(2);
    let n = parameters.poly_length().get();
    let len = parameters.rns_glwe_len();
    let table = UintDcrtTable::new(parameters.poly_length(), parameters.base_q().moduli()).unwrap();
    let gadget = parameters.gadget(DecompositionBaseLog::new(20), None);
    let sampling = parameters.encryption_parameters();
    let mut rng = StdRng::seed_from_u64(42);
    let secret = GlweSecretKey::generate(
        parameters.glwe_size(),
        parameters.secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let context = key
        .try_bind_raw(sampling, parameters.base_q(), &table)
        .unwrap();

    let crt_key = CrtGlweExpandCoeffKey::new(&gadget, sampling, &table, &secret, &key, &mut rng);
    let dcrt_key = DcrtGlweExpandCoeffKey::new(&gadget, sampling, &table, &key, &mut rng);
    let mut crt = CrtGlweExpandCoeffEvaluator::new(&crt_key, &gadget, &table);
    let mut dcrt = DcrtGlweExpandCoeffEvaluator::new(&dcrt_key, &gadget, &table);
    let mut crt_parallel = CrtGlweExpandCoeffParallelEvaluator::new(&crt_key, &gadget, &table, 2);
    let mut dcrt_parallel =
        DcrtGlweExpandCoeffParallelEvaluator::new(&dcrt_key, &gadget, &table, 2);
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();

    let mut message: Vec<_> = (1..=n as u64).collect();
    let mut ciphertext = DcrtGlweCiphertext::<Vec<u64>>::zero(len);
    let mut transformed = DcrtGlweCiphertext::<Vec<u64>>::zero(len);
    let mut crt_output = vec![CrtGlwe::<Vec<u64>>::zero(len); n];
    let mut crt_other = crt_output.clone();
    let mut dcrt_output = vec![DcrtGlweCiphertext::<Vec<u64>>::zero(len); n];
    let mut dcrt_other = dcrt_output.clone();
    let bound = support::tree_error_bound(&gadget, sampling);
    for count in [n, n / 2] {
        // Partial expansion with known zero tail yields constants. The
        // residue-class oracle below covers nonzero omitted coefficients.
        message[count..].fill(0);
        context.encrypt_encoded_crt_to(
            &support::unsigned_probe(&message, &parameters),
            &mut ciphertext,
            &mut rng,
        );
        let coefficients = ciphertext.clone().into_coeff_form(&table);
        let crt_output = &mut crt_output[..count];
        let crt_other = &mut crt_other[..count];
        let dcrt_output = &mut dcrt_output[..count];
        let dcrt_other = &mut dcrt_other[..count];
        if count == n {
            crt.expand_coefficients_to(&coefficients, crt_output);
            dcrt.expand_coefficients_to(&ciphertext, dcrt_output);
            workers.install(|| {
                crt_parallel.expand_coefficients_to(&coefficients, crt_other);
                dcrt_parallel.expand_coefficients_to(&ciphertext, dcrt_other);
            });
        } else {
            // The destinations and workspaces still hold the full expansion.
            crt.expand_partial_coefficients_to(&coefficients, crt_output);
            dcrt.expand_partial_coefficients_to(&ciphertext, dcrt_output);
            workers.install(|| {
                crt_parallel.expand_partial_coefficients_to(&coefficients, crt_other);
                dcrt_parallel.expand_partial_coefficients_to(&ciphertext, dcrt_other);
            });
        }
        for ((leaf, parallel), &expected) in crt_output.iter().zip(crt_other).zip(&message) {
            assert_eq!(leaf.as_ref(), parallel.as_ref());
            leaf.write_ntt_form(&mut transformed, &table);
            support::assert_scalar_probe(&key, &parameters, &table, &transformed, expected, bound);
        }
        for ((leaf, parallel), &expected) in dcrt_output.iter().zip(dcrt_other).zip(&message) {
            assert_eq!(leaf.as_ref(), parallel.as_ref());
            support::assert_scalar_probe(&key, &parameters, &table, leaf, expected, bound);
        }
    }

    let coefficients = ciphertext.clone().into_coeff_form(&table);
    check_expansion_counts(
        n,
        || CrtGlwe::new(vec![1; len]),
        |full, output| {
            if full {
                crt.expand_coefficients_to(&coefficients, output);
            } else {
                crt.expand_partial_coefficients_to(&coefficients, output);
            }
        },
        |full, output| {
            if full {
                crt_parallel.expand_coefficients_to(&coefficients, output);
            } else {
                crt_parallel.expand_partial_coefficients_to(&coefficients, output);
            }
        },
    );
    check_expansion_counts(
        n,
        || DcrtGlweCiphertext::new(vec![1; len]),
        |full, output| {
            if full {
                dcrt.expand_coefficients_to(&ciphertext, output);
            } else {
                dcrt.expand_partial_coefficients_to(&ciphertext, output);
            }
        },
        |full, output| {
            if full {
                dcrt_parallel.expand_coefficients_to(&ciphertext, output);
            } else {
                dcrt_parallel.expand_partial_coefficients_to(&ciphertext, output);
            }
        },
    );
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

    let parameters = support::probe_parameters(2);
    let n = parameters.poly_length();
    let table = DcrtTable::<CountingNtt>::new(n, parameters.base_q().moduli()).unwrap();
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

    let context = key
        .try_bind_raw(
            parameters.encryption_parameters(),
            parameters.base_q(),
            &table,
        )
        .unwrap();
    let gadget = parameters.gadget(DecompositionBaseLog::new(20), None);
    let bound = support::tree_error_bound(&gadget, parameters.encryption_parameters());

    let dcrt_key = DcrtGlweExpandCoeffKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &key,
        &mut rng,
    );
    let crt_key = CrtGlweExpandCoeffKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &secret,
        &key,
        &mut rng,
    );
    let mut serial = DcrtGlweExpandCoeffEvaluator::new(&dcrt_key, &gadget, &table);
    let mut parallel_one = DcrtGlweExpandCoeffParallelEvaluator::new(&dcrt_key, &gadget, &table, 1);
    let mut parallel_two = DcrtGlweExpandCoeffParallelEvaluator::new(&dcrt_key, &gadget, &table, 2);
    let mut crt_serial = CrtGlweExpandCoeffEvaluator::new(&crt_key, &gadget, &table);
    let mut crt_parallel = CrtGlweExpandCoeffParallelEvaluator::new(&crt_key, &gadget, &table, 1);
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    let length = parameters.rns_glwe_len();
    let mut ciphertext = DcrtGlweCiphertext::<Vec<u64>>::zero(length);
    let mut transformed = DcrtGlweCiphertext::<Vec<u64>>::zero(length);
    let mut one_auto_work = None;
    let mut one_crt_auto_work = None;

    // Select one irregular support per tree depth and the zero-work, paired
    // and full boundaries. Read the original message for every phase check.
    for count in [1, 2, 3, 5, 9, 17, n.get() - 1, n.get()] {
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
        workers.install(|| {
            parallel_two.expand_supported_coefficients_to(&ciphertext, &mut other);
        });
        for (expected, actual) in output.iter().zip(&other) {
            assert_eq!(expected.as_ref(), actual.as_ref());
        }
        // Check a tighter one-workspace budget at the zero-work, first
        // irregular and deepest irregular cases.
        if count == 1 || count == 3 || count == n.get() - 1 {
            workers.install(|| {
                parallel_one.expand_supported_coefficients_to(&ciphertext, &mut other);
            });
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
                expected[source - index] = i128::from(message[source]);
            }
            support::assert_probe_phase(
                &key,
                &parameters,
                &table,
                &output[index],
                &expected,
                bound,
            );
            crt_output[index].write_ntt_form(&mut transformed, &table);
            support::assert_probe_phase(&key, &parameters, &table, &transformed, &expected, bound);
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
