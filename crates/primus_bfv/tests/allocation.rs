//! Allocation contracts are checked separately from performance measurements.

use primus_bfv::{BfvDecryptWorkspace, BfvParameters, BfvPublicKeyEncryptor, BfvSecretKeyContext};
use primus_glwe_rns::{
    DcrtGlweCiphertext, DcrtGlwePublicKey, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
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
    let table = U64DcrtTable::new(parameters.poly_length(), parameters.cipher_moduli()).unwrap();
    let mut rng = StdRng::seed_from_u64(91);
    let key = GlweSecretKey::generate(
        parameters.glwe_size(),
        parameters.secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, &table);
    let public = DcrtGlwePublicKey::new(
        &key,
        parameters.encryption_parameters(),
        parameters.base_q(),
        &table,
        &mut rng,
    );
    let context = BfvSecretKeyContext::try_new(&key, &parameters, &table).unwrap();
    let mut encryptor = BfvPublicKeyEncryptor::try_new(&public, &parameters, &table).unwrap();
    let mut workspace = BfvDecryptWorkspace::new(&parameters);
    let input = Polynomial(vec![3; 32]);
    let crt = CrtPolynomial(vec![3; parameters.rns_poly_len()]);
    let mut ciphertext = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let mut phase = DcrtPolynomial::<Vec<u64>>::zero(parameters.rns_poly_len());
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
        observe(|| context.encrypt_plaintext_crt_to(&crt, &mut ciphertext, &mut rng)).1,
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
        observe(|| encryptor.encrypt_plaintext_crt_to(&crt, &mut ciphertext, &mut rng)).1,
        0
    );
    assert_eq!(observe(|| encryptor.workspace_mut().zeroize()).1, 0);
    let (ciphertext, count) = observe(|| encryptor.encrypt_plaintext_crt(&crt, &mut rng));
    assert_eq!(count, 1);
    assert_eq!(context.decrypt(&ciphertext, &mut workspace), input);
    workspace.zeroize();
    assert_eq!(
        observe(|| context.decrypt_to(&ciphertext, &mut output, &mut workspace)).1,
        0
    );
    assert_eq!(output, input);
}
