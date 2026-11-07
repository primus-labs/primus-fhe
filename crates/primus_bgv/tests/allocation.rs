//! Prepared coefficient operations retain their full-ring allocations.
use primus_bgv::evaluation::{
    BgvAutomorphism, BgvEvaluator, BgvKeySwitcher, BgvModulusSwitch, BgvMultiplication,
};
use primus_bgv::keys::BgvEvaluationKeyConfig;
use primus_bgv::{BgvClient, BgvContext, BgvParameters, PlaintextEmbedding};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::{DcrtPolynomial, Polynomial};
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
    let factor_one = [
        1_125_899_906_248_961,
        1_125_899_906_051_329,
        1_125_899_904_322_049,
    ];
    let general = [
        1_125_899_905_351_681,
        1_125_899_905_744_897,
        1_125_899_906_629_633,
    ];
    for primes in [factor_one, general] {
        for hybrid in [false, true] {
            prepared_request(primes, hybrid);
        }
    }
}
fn prepared_request(primes: [u64; 3], hybrid: bool) {
    let moduli = primes.map(BarrettModulus::new);
    let context = BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
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
    let mut plaintext_scratch = vec![u64::MAX; context.rns_poly_len(0)];
    let mut recipient = BgvClient::generate(&context, &mut rng);
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let config0: BgvEvaluationKeyConfig = if hybrid {
        context
            .hybrid_key_parameters(0, 3, &[1_152_921_504_606_830_593])
            .unwrap()
            .into()
    } else {
        config.into()
    };
    let config1: BgvEvaluationKeyConfig = if hybrid {
        context
            .hybrid_key_parameters(1, 3, &[1_152_921_504_606_830_593])
            .unwrap()
            .into()
    } else {
        config.into()
    };
    let relin_key0 = client.relinearization_key(0, config0, &mut rng).unwrap();
    let relin_key1 = client
        .relinearization_key(1, config1.clone(), &mut rng)
        .unwrap();
    #[cfg(feature = "batching")]
    let auto_key = client
        .row_rotation_key(
            1,
            &context.batching_encoder().unwrap(),
            1,
            config1.clone(),
            &mut rng,
        )
        .unwrap();
    #[cfg(not(feature = "batching"))]
    let auto_key = client
        .automorphism_key(1, 5, config1.clone(), &mut rng)
        .unwrap();
    let switch_key = recipient
        .key_switching_key(&client, 1, config1.clone(), &mut rng)
        .unwrap();
    let mut multiplication0 = BgvMultiplication::try_new(&context, &relin_key0).unwrap();
    let mut multiplication1 = BgvMultiplication::try_new(&context, &relin_key1).unwrap();
    let mut automorphism = BgvAutomorphism::try_new(&context, &auto_key).unwrap();
    let mut key_switcher = BgvKeySwitcher::try_new(&context, &switch_key).unwrap();
    let mut drop0 = BgvModulusSwitch::new(&context, 0);
    let mut drop1 = BgvModulusSwitch::new(&context, 1);
    let mut squared0 = context.new_ciphertext(0);
    let mut reduced1 = context.new_ciphertext(1);
    let mut squared1 = context.new_ciphertext(1);
    let mut mixed = context.new_ciphertext(1);
    let mut evaluator1 = BgvEvaluator::new(&context, 1);
    let mut rotated1 = context.new_ciphertext(1);
    let mut switched1 = context.new_ciphertext(1);
    let mut reduced2 = context.new_ciphertext(2);
    let mut partial_phase = DcrtPolynomial(vec![0; context.rns_poly_len(0)]);
    ALLOCATIONS.with(|count| count.set(0));
    ACTIVE.with(|enabled| enabled.set(true));
    client.encrypt_to(&input, &mut ciphertext, &mut rng);
    client
        .partial_phase_to(&ciphertext, 0, &mut partial_phase)
        .unwrap();
    std::hint::black_box(&partial_phase);
    client.decrypt_at_level_to(&ciphertext, 0, &mut output);
    encryptor.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
    client.decrypt_at_level_to(&ciphertext, 0, &mut output);
    // All participants' public/private inputs are freshly encrypted; the entire
    // linear/plaintext/recovery workflow reuses persistent prepared storage.
    client.encrypt_centered_to(&input, &mut ciphertext, &mut rng);
    encryptor.encrypt_to(&input, &mut second, &mut rng);
    {
        // A worker can bind an already allocated dirty prefix for one call;
        // neither this lightweight constructor nor the operation allocates.
        let mut borrowed =
            BgvEvaluator::with_plaintext_scratch(&context, 0, plaintext_scratch.as_mut_slice());
        borrowed.mul_plain_to(&ciphertext, &negative_one, &mut combined, embedding);
        evaluator.mul_plain_to(&ciphertext, &negative_one, &mut evaluated, embedding);
        assert_eq!(combined, evaluated);
    }
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
    multiplication0.multiply_to(&combined, &combined, &mut squared0);
    drop0.switch_to(&squared0, &mut reduced1);
    multiplication1.square_to(&reduced1, &mut squared1);
    // Drop-then-square and just drop carry different factors on general chains.
    assert_eq!(
        squared1.correction_factor() == reduced1.correction_factor(),
        primes[2] % 193 == 1,
    );
    evaluator1.add_to(&squared1, &reduced1, &mut mixed);
    evaluator1.sub_assign(&mut mixed, &reduced1);
    evaluator1.add_plain_assign(&mut mixed, &ones, embedding);
    evaluator1.mul_plain_assign(&mut mixed, &negative_one, embedding);
    multiplication1.square_assign(&mut reduced1);
    automorphism.apply_to(&mixed, &mut rotated1);
    key_switcher.switch_to(&rotated1, &mut switched1);
    drop1.switch_to(&switched1, &mut reduced2);
    recipient.decrypt_at_level_to(&reduced2, 2, &mut output);
    ACTIVE.with(|enabled| enabled.set(false));
    let count = ALLOCATIONS.with(Cell::get);
    assert_eq!(count, 0);
    assert_eq!(reduced1.as_ref(), squared1.as_ref());
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
    for (i, &coefficient) in fourth.iter().enumerate() {
        let x = (192 - coefficient).rem_euclid(193);
        let degree = i * 5;
        expected[degree % 32] = if degree / 32 % 2 == 0 {
            x
        } else {
            (193 - x) % 193
        };
    }
    assert_eq!(output.as_ref(), expected);
}
