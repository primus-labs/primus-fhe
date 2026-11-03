//! Prepared coefficient operations retain their full-ring allocations.
use primus_bgv::{BgvClient, BgvContext, BgvEvaluator, BgvParameters, PlaintextEmbedding};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
thread_local! { static ACTIVE: Cell<bool> = const { Cell::new(false) }; static ALLOCATIONS: Cell<usize> = const { Cell::new(0) }; }
struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ACTIVE.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, length: usize) -> *mut u8 {
        if ACTIVE.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        }
        unsafe { System.realloc(pointer, layout, length) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
#[test]
fn private_public_and_exact_wide_recovery_reuse_prepared_storage() {
    let moduli = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ]
    .map(BarrettModulus::new);
    let context = BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(32),
            BarrettModulus::new(193),
            &moduli,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(847);
    let mut client = BgvClient::generate(&context, &mut rng);
    let key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&key).unwrap();
    let input = Polynomial(
        (0..32)
            .map(|i| if i % 2 == 0 { 192 } else { 0 })
            .collect::<Vec<_>>(),
    );
    let mut output = Polynomial::<Vec<u64>>::zero(32);
    let mut ciphertext = context.new_ciphertext();
    let mut second = context.new_ciphertext();
    let mut combined = context.new_ciphertext();
    let mut evaluated = context.new_ciphertext();
    let ones = Polynomial(vec![1; 32]);
    let mut negative_one = vec![0; 32];
    negative_one[0] = 192;
    let negative_one = Polynomial(negative_one);
    let embedding = PlaintextEmbedding::Centered;
    let mut evaluator = BgvEvaluator::new(&context);
    ALLOCATIONS.with(|count| count.set(0));
    ACTIVE.with(|enabled| enabled.set(true));
    client.encrypt_to(&input, &mut ciphertext, &mut rng);
    client.decrypt_to(&ciphertext, &mut output);
    encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
    client.decrypt_to(&ciphertext, &mut output);
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
    client.decrypt_to(&combined, &mut output);
    ACTIVE.with(|enabled| enabled.set(false));
    let count = ALLOCATIONS.with(Cell::get);
    assert_eq!(count, 0);
    let expected: Vec<_> = input
        .as_ref()
        .iter()
        .map(|&value| (value + 2) % 193)
        .collect();
    assert_eq!(output.as_ref(), expected);
}
