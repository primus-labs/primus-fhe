//! Allocation contracts are checked separately from performance measurements.

use primus_bfv::{
    BfvCiphertext, BfvClient, BfvContext, BfvDecryptWorkspace, BfvEvaluator, BfvModulusSwitch,
    BfvParameters, BfvPublicKey, BfvPublicKeyEncryptor, BfvSecretKeyContext, PlaintextEmbedding,
};
use primus_glwe_rns::{DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial, Polynomial};
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
fn prepared_calls_allocate_nothing_and_convenience_allocates_only_the_result() {
    let parameters = BfvParameters::new(
        PolyLength::new(32),
        BarrettModulus::new(17),
        BarrettModulus::new(257),
        &[65_537, 114_689].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        1.0,
    );
    let table = U64DcrtTable::new(parameters.poly_length(), parameters.base_q().moduli()).unwrap();
    let mut rng = StdRng::seed_from_u64(91);
    let key = GlweSecretKey::generate(
        parameters.size().glwe_size(),
        parameters.encryption_parameters().secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, &table);
    let context = BfvSecretKeyContext::try_new(&key, &parameters, &table).unwrap();
    let public = BfvPublicKey::new(&context, &mut rng);
    let mut encryptor = BfvPublicKeyEncryptor::try_new(&public, &parameters, &table).unwrap();
    let mut workspace = BfvDecryptWorkspace::new(&parameters);
    let input = Polynomial(vec![3; 32]);
    let crt = CrtPolynomial(vec![3; parameters.size().rns_poly_len()]);
    let mut encoded = CrtPolynomial::<Vec<u64>>::zero(parameters.size().rns_poly_len());
    parameters
        .codec()
        .encode_coeffs_to(&input, &mut encoded, PlaintextEmbedding::Unsigned);
    let mut raw = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    let mut ciphertext = BfvCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    let mut phase = DcrtPolynomial::<Vec<u64>>::zero(parameters.size().rns_poly_len());
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
        observe(|| ciphertext.write_raw_glwe_to(&mut raw, &parameters)).1,
        0
    );
    assert_eq!(
        observe(|| ciphertext.set_from_raw_glwe(&raw, &parameters)).1,
        0
    );
    assert_eq!(observe(|| context.phase_to(&ciphertext, &mut phase)).1, 0);
    assert_eq!(
        observe(|| context.decrypt_to(&ciphertext, &mut output, &mut workspace)).1,
        0
    );
    assert_eq!(output, input);
    let (decrypted, count) = observe(|| context.decrypt(&ciphertext, &mut workspace));
    assert_eq!(count, 1);
    assert_eq!(decrypted, input);
    assert_eq!(
        observe(|| context.encrypt_zeros_to(&mut ciphertext, &mut rng)).1,
        0
    );
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
    assert_eq!(observe(|| encryptor.workspace_mut().zeroize()).1, 0);
    let (ciphertext, count) = observe(|| encryptor.encrypt_plaintext_lift_crt(&crt, &mut rng));
    assert_eq!(count, 1);
    assert_eq!(context.decrypt(&ciphertext, &mut workspace), input);
    workspace.zeroize();
    assert_eq!(
        observe(|| context.decrypt_to(&ciphertext, &mut output, &mut workspace)).1,
        0
    );
    assert_eq!(output, input);
}

#[test]
fn prepared_leveled_request_and_each_evaluator_family_allocate_nothing() {
    let parameters = BfvParameters::new(
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
    );
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
            client.decrypt_to(&final_ciphertext, 2, &mut decoded);
        })
        .1,
        0
    );
    let (allocated, count) = observe(|| client.decrypt(&final_ciphertext, 2));
    assert_eq!(count, 1);
    assert_eq!(allocated, decoded);
}
