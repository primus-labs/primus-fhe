//! Allocation contracts are checked separately from performance measurements.

use primus_bfv::{
    BfvAutomorphism, BfvCiphertext, BfvClient, BfvContext, BfvDecryptWorkspace, BfvEvaluator,
    BfvKeySwitcher, BfvLeveledMultiplication, BfvModulusSwitch, BfvMultiplier, BfvParameters,
    BfvPublicKey, BfvPublicKeyEncryptor, BfvRelinearizer, BfvSecretKeyContext, PlaintextEmbedding,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_glwe_rns::{DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
use zeroize::Zeroize;

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}

struct Allocator;

fn record(pointer: *mut u8) {
    if !pointer.is_null() {
        let _ = COUNT.try_with(|count| {
            if let Some(value) = count.get() {
                count.set(Some(value + 1));
            }
        });
    }
}

// SAFETY: The original pointer/layout/size are forwarded unchanged to System.
// Counting uses nonallocating thread-local Cells and never inspects allocations.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplied the required GlobalAlloc layout.
        let pointer = unsafe { System.alloc(layout) };
        record(pointer);
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The same layout is forwarded to System.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record(pointer);
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The original allocation contract is forwarded unchanged.
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        record(pointer);
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The original allocation and layout are returned to System.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Observation;
impl Drop for Observation {
    fn drop(&mut self) {
        COUNT.with(|count| count.set(None));
    }
}

fn observe<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    COUNT.with(|count| {
        assert!(count.get().is_none());
        count.set(Some(0));
    });
    let guard = Observation;
    let output = operation();
    let count = COUNT.with(|count| count.get().unwrap());
    drop(guard);
    (output, count)
}

#[test]
fn temporary_working_basis_multiply_and_key_operations_allocate_nothing() {
    let parameters = BfvParameters::try_new(
        PolyLength::new(32),
        BarrettModulus::new(193),
        BarrettModulus::new((1 << 61) - 1),
        &[
            1_125_899_906_248_961,
            1_125_899_906_051_329,
            1_125_899_904_322_049,
        ]
        .map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        1.0,
    )
    .unwrap();
    let context = BfvContext::try_with_levels(parameters, 3).unwrap();
    let mut rng = StdRng::seed_from_u64(0x26_a110c);
    let client = BfvClient::generate(&context, &mut rng);
    let target = BfvClient::generate(&context, &mut rng);
    let input = client.encrypt_centered(&Polynomial::new(vec![1; 32]), &mut rng);
    let mut output = context.new_ciphertext(0);
    let mut multiplier = BfvMultiplier::try_with_default_basis(&context, 0).unwrap();
    let mut quadratic = context.new_quadratic_ciphertext(0);
    multiplier.square_to(&input, &mut quadratic);
    for working in [1, 2] {
        for hybrid in [false, true] {
            let config = if hybrid {
                context
                    .hybrid_key_parameters(working, 3, &[1_152_921_504_606_830_593])
                    .unwrap()
                    .into()
            } else {
                primus_bfv::BfvEvaluationKeyConfig::Radix(DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                })
            };
            let relin_key = client
                .relinearization_key(working, config.clone(), &mut rng)
                .unwrap();
            let switch_key = client
                .key_switching_key(&target, working, config.clone(), &mut rng)
                .unwrap();
            let auto_key = client
                .automorphism_key(working, 5, config, &mut rng)
                .unwrap();
            let mut request = BfvLeveledMultiplication::try_new(&context, 0, &relin_key).unwrap();
            let mut relin =
                BfvRelinearizer::try_with_working_level(&context, 0, &relin_key).unwrap();
            let mut switch =
                BfvKeySwitcher::try_with_working_level(&context, 0, &switch_key).unwrap();
            let mut auto = BfvAutomorphism::try_with_working_level(&context, 0, &auto_key).unwrap();
            let mut inplace = input.clone();
            assert_eq!(
                observe(|| request.multiply_to(&input, &input, &mut output)).1,
                0
            );
            assert_eq!(observe(|| request.square_to(&input, &mut output)).1, 0);
            assert_eq!(observe(|| request.square_assign(&mut inplace)).1, 0);
            assert_eq!(
                observe(|| relin.relinearize_to(&quadratic, &mut output)).1,
                0
            );
            assert_eq!(observe(|| switch.switch_to(&input, &mut output)).1, 0);
            assert_eq!(observe(|| auto.apply_to(&input, &mut output)).1, 0);
        }
    }
}

#[test]
fn prepared_calls_allocate_nothing_and_convenience_allocates_only_the_result() {
    let parameters = BfvParameters::try_new(
        PolyLength::new(32),
        BarrettModulus::new(17),
        BarrettModulus::new(257),
        &[65_537, 114_689].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        1.0,
    )
    .unwrap();
    let owner = BfvContext::try_new(parameters).unwrap();
    let parameters = owner.parameters();
    let table = owner.table();
    let mut rng = StdRng::seed_from_u64(91);
    let key = GlweSecretKey::generate(
        parameters.size().glwe_size(),
        parameters.encryption_parameters().secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, table);
    let context = BfvSecretKeyContext::try_new(&key, &owner).unwrap();
    let public = BfvPublicKey::new(&context, &mut rng);
    let mut encryptor = BfvPublicKeyEncryptor::try_new(&public, &owner).unwrap();
    let mut workspace = BfvDecryptWorkspace::new(parameters);
    let input = Polynomial(vec![3; 32]);
    let crt = CrtPolynomial(vec![3; parameters.size().rns_poly_len()]);
    let mut encoded = CrtPolynomial::<Vec<u64>>::zero(parameters.size().rns_poly_len());
    parameters
        .codec()
        .encode_coeffs_to(&input, &mut encoded, PlaintextEmbedding::Unsigned);
    let mut raw = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    let mut ciphertext = BfvCiphertext::<Vec<u64>>::zero_raw(parameters.size().rns_glwe_len());
    let mut output = Polynomial::<Vec<u64>>::zero(32);

    assert_eq!(
        observe(|| context.encrypt_to(&input, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(
        observe(|| context.encrypt_centered_to(&input, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(
        observe(|| context.encrypt_plaintext_lift_crt_to(&crt, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(
        observe(|| context.encrypt_encoded_crt_to(&encoded, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(
        observe(|| ciphertext.write_raw_glwe_to(&mut raw, parameters)).1,
        0
    );
    assert_eq!(
        observe(|| ciphertext.set_from_raw_glwe(&raw, parameters)).1,
        0
    );
    assert_eq!(
        observe(|| context.decrypt_to(&ciphertext, &mut output, &mut workspace)).1,
        0
    );
    assert_eq!(output, input);
    let (decrypted, count) = observe(|| context.decrypt(&ciphertext, &mut workspace));
    assert_eq!(count, 1);
    assert_eq!(decrypted, input);
    assert_eq!(
        observe(|| encryptor.encrypt_to(&input, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(
        observe(|| encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(
        observe(|| encryptor.encrypt_plaintext_lift_crt_to(&crt, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(
        observe(|| encryptor.encrypt_encoded_crt_to(&encoded, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(observe(|| encryptor.zeroize()).1, 0);
    let (fresh, count) = observe(|| encryptor.encrypt(&input, &mut rng));
    assert_eq!(count, 1);
    assert_eq!(context.decrypt(&fresh, &mut workspace), input);
    let (fresh, count) = observe(|| encryptor.encrypt_centered(&input, &mut rng));
    assert_eq!(count, 1);
    assert_eq!(context.decrypt(&fresh, &mut workspace), input);
    workspace.zeroize();
    assert_eq!(
        observe(|| context.decrypt_to(&ciphertext, &mut output, &mut workspace)).1,
        0
    );
    assert_eq!(output, input);
}

#[test]
fn prepared_leveled_request_and_each_evaluator_family_allocate_nothing() {
    let parameters = BfvParameters::try_new(
        PolyLength::new(32),
        BarrettModulus::new(257),
        BarrettModulus::new(2_199_023_190_017),
        &[
            1_125_899_906_826_241,
            1_125_899_906_629_633,
            1_125_899_906_031_617,
        ]
        .map(BarrettModulus::new),
        SecretKeyDistr::UniformBinary,
        1.0,
    )
    .unwrap();
    let context = BfvContext::try_with_levels(parameters, 3).unwrap();
    let mut rng = StdRng::seed_from_u64(0x6063);
    let mut client = BfvClient::generate(&context, &mut rng);
    let mut evaluator = BfvEvaluator::new(&context, 0);
    let mut first_drop = BfvModulusSwitch::new(&context, 0);
    let mut second_drop = BfvModulusSwitch::new(&context, 1);
    let message = Polynomial(vec![1; 32]);
    let multiplier = Polynomial(vec![256; 32]);
    let mut input = context.new_ciphertext(0);
    let mut output = context.new_ciphertext(0);
    let mut middle = context.new_ciphertext(1);
    let mut final_ciphertext = context.new_ciphertext(2);
    let mut decoded = Polynomial::<Vec<u64>>::zero(32);
    let embedding = PlaintextEmbedding::Centered;
    client.encrypt_centered_to(&message, &mut input, &mut rng);
    assert_eq!(
        observe(|| evaluator.add_to(&input, &input, &mut output)).1,
        0
    );
    assert_eq!(observe(|| evaluator.add_assign(&mut output, &input)).1, 0);
    assert_eq!(
        observe(|| evaluator.sub_to(&input, &input, &mut output)).1,
        0
    );
    assert_eq!(observe(|| evaluator.sub_assign(&mut output, &input)).1, 0);
    assert_eq!(observe(|| evaluator.neg_to(&input, &mut output)).1, 0);
    assert_eq!(observe(|| evaluator.neg_assign(&mut output)).1, 0);
    assert_eq!(
        observe(|| evaluator.add_plain_to(&input, &message, &mut output, embedding)).1,
        0
    );
    assert_eq!(
        observe(|| evaluator.add_plain_assign(&mut output, &message, embedding)).1,
        0
    );
    assert_eq!(
        observe(|| evaluator.mul_plain_to(&input, &multiplier, &mut output, embedding)).1,
        0
    );
    assert_eq!(
        observe(|| evaluator.mul_plain_assign(&mut output, &multiplier, embedding)).1,
        0
    );
    assert_eq!(
        observe(|| {
            client.encrypt_centered_to(&message, &mut input, &mut rng);
            evaluator.add_plain_assign(&mut input, &message, embedding);
            evaluator.mul_plain_to(&input, &multiplier, &mut output, embedding);
            first_drop.switch_to(&output, &mut middle);
            second_drop.switch_to(&middle, &mut final_ciphertext);
            client.decrypt_at_level_to(&final_ciphertext, 2, &mut decoded);
        })
        .1,
        0
    );
    let (allocated, count) = observe(|| client.decrypt_at_level(&final_ciphertext, 2));
    assert_eq!(count, 1);
    assert_eq!(allocated, decoded);
}

#[test]
fn complete_exact_multiplication_and_native_keys_reuse_prepared_storage() {
    let moduli = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ]
    .map(BarrettModulus::new);
    let context = BfvContext::try_with_levels(
        BfvParameters::try_coefficients(
            PolyLength::new(32),
            BarrettModulus::new(193),
            &moduli,
            SecretKeyDistr::SparseTernary,
            0.849,
        )
        .unwrap(),
        3,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(847);
    let mut client = BfvClient::generate(&context, &mut rng);
    let key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&key).unwrap();
    let input = Polynomial(
        (0..32)
            .map(|i| if i % 2 == 0 { 192 } else { 0 })
            .collect::<Vec<_>>(),
    );
    let mut output = Polynomial::<Vec<u64>>::zero(32);
    let mut ciphertext = context.new_ciphertext(0);
    let mut second = context.new_ciphertext(0);
    let mut combined = context.new_ciphertext(0);
    let mut evaluated = context.new_ciphertext(0);
    let ones = Polynomial(vec![1; 32]);
    let mut negative_one = vec![0; 32];
    negative_one[0] = 192;
    let negative_one = Polynomial(negative_one);
    let embedding = PlaintextEmbedding::Centered;
    let mut evaluator = BfvEvaluator::new(&context, 0);
    let auxiliary = [
        1_152_921_504_606_584_833,
        1_152_921_504_598_720_513,
        1_152_921_504_592_429_057,
    ];
    let mut multiplier0 = primus_bfv::BfvMultiplier::try_new(&context, 0, &auxiliary).unwrap();
    let mut multiplier1 = primus_bfv::BfvMultiplier::try_new(&context, 1, &auxiliary).unwrap();
    let mut recipient = BfvClient::generate(&context, &mut rng);
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let relin_key0 = client.relinearization_key(0, config, &mut rng).unwrap();
    let relin_key1 = client.relinearization_key(1, config, &mut rng).unwrap();
    #[cfg(feature = "batching")]
    let auto_key = client
        .row_rotation_key(1, &context.batching_encoder().unwrap(), 1, config, &mut rng)
        .unwrap();
    #[cfg(not(feature = "batching"))]
    let auto_key = client.automorphism_key(1, 5, config, &mut rng).unwrap();
    let switch_key = recipient
        .key_switching_key(&client, 1, config, &mut rng)
        .unwrap();
    let mut relin0 = BfvRelinearizer::try_new(&context, &relin_key0).unwrap();
    let mut relin1 = BfvRelinearizer::try_new(&context, &relin_key1).unwrap();
    let mut request0 = primus_bfv::BfvMultiplication::try_new(&context, &relin_key0).unwrap();
    let mut request1 = primus_bfv::BfvMultiplication::try_new(&context, &relin_key1).unwrap();
    let (fresh, count) = observe(|| client.encrypt(&input, &mut rng));
    assert_eq!(count, 1);
    client.decrypt_at_level_to(&fresh, 0, &mut output);
    assert_eq!(output, input);
    let (fresh, count) = observe(|| client.encrypt_centered(&input, &mut rng));
    assert_eq!(count, 1);
    client.decrypt_at_level_to(&fresh, 0, &mut output);
    assert_eq!(output, input);
    let mut automorphism = BfvAutomorphism::try_new(&context, &auto_key).unwrap();
    let mut key_switcher = BfvKeySwitcher::try_new(&context, &switch_key).unwrap();
    let mut drop0 = BfvModulusSwitch::new(&context, 0);
    let mut drop1 = BfvModulusSwitch::new(&context, 1);
    let mut tensor0 = context.new_quadratic_ciphertext(0);
    let mut tensor1 = context.new_quadratic_ciphertext(1);
    let mut squared0 = context.new_ciphertext(0);
    let mut reduced1 = context.new_ciphertext(1);
    let mut squared1 = context.new_ciphertext(1);
    let mut rotated1 = context.new_ciphertext(1);
    let mut switched1 = context.new_ciphertext(1);
    let mut reduced2 = context.new_ciphertext(2);
    let (_, count) = observe(|| {
        client.encrypt_to(&input, &mut ciphertext, &mut rng);
        client.decrypt_at_level_to(&ciphertext, 0, &mut output);
        encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
        client.decrypt_at_level_to(&ciphertext, 0, &mut output);
        // All participants' public/private inputs are freshly encrypted; the entire
        // linear/plaintext/recovery workflow reuses persistent prepared storage.
        client.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
        encryptor.encrypt_to(&input, &mut second, &mut rng);
        evaluator.add_to(&ciphertext, &second, &mut combined);
        evaluator.add_assign(&mut combined, &ciphertext);
        evaluator.sub_to(&combined, &ciphertext, &mut evaluated);
        evaluator.sub_assign(&mut evaluated, &second);
        evaluator.neg_to(&evaluated, &mut combined);
        evaluator.neg_assign(&mut combined);
        evaluator.add_plain_to(&combined, &ones, &mut evaluated, embedding);
        evaluator.add_plain_assign(&mut evaluated, &ones, embedding);
        evaluator.mul_plain_to(&evaluated, &negative_one, &mut combined, embedding);
        evaluator.mul_plain_assign(&mut combined, &negative_one, embedding);
        client.decrypt_at_level_to(&combined, 0, &mut output);
        multiplier0.multiply_to(&combined, &combined, &mut tensor0);
        relin0.relinearize_to(&tensor0, &mut squared0);
        request0.multiply_to(&combined, &combined, &mut squared0);
        drop0.switch_to(&squared0, &mut reduced1);
        multiplier1.square_to(&reduced1, &mut tensor1);
        relin1.relinearize_to(&tensor1, &mut squared1);
        request1.square_to(&reduced1, &mut squared1);
        squared1.as_mut().copy_from_slice(reduced1.as_ref());
        request1.square_assign(&mut squared1);
        automorphism.apply_to(&squared1, &mut rotated1);
        key_switcher.switch_to(&rotated1, &mut switched1);
        drop1.switch_to(&switched1, &mut reduced2);
        recipient.decrypt_at_level_to(&reduced2, 2, &mut output);
    });
    assert_eq!(count, 0);
    let expected: Vec<_> = input
        .as_ref()
        .iter()
        .map(|&value| (value + 2) % 193)
        .collect();
    let square = |a: &[u64]| {
        let mut result = vec![0i128; a.len()];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in a.iter().enumerate() {
                let degree = i + j;
                result[degree % a.len()] += if degree < a.len() {
                    i128::from(x) * i128::from(y)
                } else {
                    -i128::from(x) * i128::from(y)
                };
            }
        }
        result
            .into_iter()
            .map(|x| x.rem_euclid(193) as u64)
            .collect::<Vec<_>>()
    };
    let fourth = square(&square(&expected));
    let mut expected = vec![0; 32];
    for (i, &x) in fourth.iter().enumerate() {
        let degree = i * 5;
        expected[degree % 32] = if degree / 32 % 2 == 0 {
            x
        } else {
            (193 - x) % 193
        };
    }
    assert_eq!(output.as_ref(), expected);
}

#[test]
fn collective_partial_phase_and_consuming_prepared_lookup_allocate_nothing() {
    use primus_bfv::{BfvCollectiveRelinearization, BfvRawQuadraticAggregate};
    use primus_distr::ErrorDistribution;
    use primus_poly::DcrtPolynomial;
    let context = BfvContext::try_new(
        BfvParameters::try_with_error_distribution(
            PolyLength::new(32),
            BarrettModulus::new(257),
            BarrettModulus::new((1 << 61) - 1),
            &[1_125_899_906_248_961, 1_125_899_906_051_329].map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x0015_bf03);
    let key = BfvClient::generate(&context, &mut rng).into_secret_key();
    let plan = BfvCollectiveRelinearization::try_new(
        &context,
        0,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: None,
        },
        &mut rng,
    )
    .unwrap();
    let (message, state) = plan.start(&key, &mut rng).unwrap();
    let mut sum = plan.aggregate(1).unwrap();
    sum.add(&message).unwrap();
    let round1 = plan.freeze_round1(sum).unwrap();
    let message = state.round2(&round1, &mut rng).unwrap();
    let mut sum = round1.aggregate(1).unwrap();
    sum.add(&message).unwrap();
    let lookup = round1.finalize_lookup(sum).unwrap().prepare();
    let len = context.rns_poly_len(0);
    let tensor = BfvRawQuadraticAggregate::try_new(&context, 0, vec![1; 3 * len]).unwrap();
    let mut output = context.new_ciphertext(0);
    let mut partial = DcrtPolynomial(vec![0; len]);
    let (result, count) = observe(|| lookup.apply_to(tensor, &mut output));
    result.unwrap();
    assert_eq!(count, 0);
    let client = BfvClient::try_from_secret_key(&context, key).unwrap();
    let (result, count) = observe(|| client.partial_phase_to(&output, 0, &mut partial));
    result.unwrap();
    assert_eq!(count, 0);
}
