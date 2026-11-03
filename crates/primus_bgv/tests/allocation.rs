//! Prepared coefficient operations retain their full-ring allocations.
use primus_bgv::{
    BgvAutomorphism, BgvClient, BgvContext, BgvEvaluator, BgvKeySwitcher, BgvModulusSwitch,
    BgvParameters, BgvRelinearizer, PlaintextEmbedding,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
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
    let context = BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(32),
            BarrettModulus::new(193),
            &moduli,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
        3,
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
    let mut ciphertext = context.new_ciphertext(0);
    let mut second = context.new_ciphertext(0);
    let mut combined = context.new_ciphertext(0);
    let mut evaluated = context.new_ciphertext(0);
    let ones = Polynomial(vec![1; 32]);
    let mut negative_one = vec![0; 32];
    negative_one[0] = 192;
    let negative_one = Polynomial(negative_one);
    let embedding = PlaintextEmbedding::Centered;
    let mut evaluator = BgvEvaluator::new(&context, 0);
    let evaluator1 = BgvEvaluator::new(&context, 1);
    let mut recipient = BgvClient::generate(&context, &mut rng);
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let relin_key0 = client.relinearization_key(0, config, &mut rng).unwrap();
    let relin_key1 = client.relinearization_key(1, config, &mut rng).unwrap();
    let auto_key = client.automorphism_key(1, 5, config, &mut rng).unwrap();
    let switch_key = recipient
        .key_switching_key(&client, 1, config, &mut rng)
        .unwrap();
    let mut relin0 = BgvRelinearizer::try_new(&context, 0, &relin_key0).unwrap();
    let mut relin1 = BgvRelinearizer::try_new(&context, 1, &relin_key1).unwrap();
    let mut automorphism = BgvAutomorphism::try_new(&context, 1, &auto_key).unwrap();
    let mut key_switcher = BgvKeySwitcher::try_new(&context, 1, &switch_key).unwrap();
    let mut drop0 = BgvModulusSwitch::new(&context, 0);
    let mut drop1 = BgvModulusSwitch::new(&context, 1);
    let mut tensor0 = context.new_quadratic_ciphertext(0);
    let mut tensor1 = context.new_quadratic_ciphertext(1);
    let mut squared0 = context.new_ciphertext(0);
    let mut reduced1 = context.new_ciphertext(1);
    let mut squared1 = context.new_ciphertext(1);
    let mut rotated1 = context.new_ciphertext(1);
    let mut switched1 = context.new_ciphertext(1);
    let mut reduced2 = context.new_ciphertext(2);
    ALLOCATIONS.with(|count| count.set(0));
    ACTIVE.with(|enabled| enabled.set(true));
    client.encrypt_to(&input, &mut ciphertext, &mut rng);
    client.decrypt_to(&ciphertext, 0, &mut output);
    encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
    client.decrypt_to(&ciphertext, 0, &mut output);
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
    client.decrypt_to(&combined, 0, &mut output);
    evaluator.mul_to(&combined, &combined, &mut tensor0);
    relin0.relinearize_to(&tensor0, &mut squared0);
    drop0.switch_to(&squared0, &mut reduced1);
    evaluator1.square_to(&reduced1, &mut tensor1);
    relin1.relinearize_to(&tensor1, &mut squared1);
    automorphism.apply_to(&squared1, &mut rotated1);
    key_switcher.switch_to(&rotated1, &mut switched1);
    drop1.switch_to(&switched1, &mut reduced2);
    recipient.decrypt_to(&reduced2, 2, &mut output);
    ACTIVE.with(|enabled| enabled.set(false));
    let count = ALLOCATIONS.with(Cell::get);
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
