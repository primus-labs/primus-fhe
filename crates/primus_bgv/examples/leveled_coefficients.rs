//! Planned ordinary circuit: public phase budgets, role keys and two prime drops.
//! Run: cargo run -p primus_bgv --example leveled_coefficients
//! Native Hybrid keys: append -- --hybrid.

use primus_bgv::evaluation::{
    BgvAutomorphism, BgvEvaluator, BgvKeySwitcher, BgvModulusSwitch, BgvMultiplication,
};
use primus_bgv::planning::{
    BgvBudgetBackend, BgvCircuitOperation, BgvCircuitPlan, BgvParameterRequest, BgvPlaintextBounds,
};
use primus_bgv::{BgvClient, ErrorDistribution, PlaintextEmbedding, SecretKeyDistr};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const P: u64 = 193;

fn product(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
    let mut output = vec![0i128; N];
    for (i, &left) in lhs.iter().enumerate() {
        for (j, &right) in rhs.iter().enumerate() {
            output[(i + j) % N] +=
                i128::from(left) * i128::from(right) * if i + j < N { 1 } else { -1 };
        }
    }
    output
        .iter()
        .map(|value| value.rem_euclid(i128::from(P)) as u64)
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // N/prime resources are explicit; generation validates real NTT primes.
    // These small functional parameters do not establish an RLWE security level.
    let context = BgvParameterRequest {
        poly_length: PolyLength::new(N),
        plaintext_modulus: P,
        ciphertext_prime_bits: 50,
        ciphertext_prime_count: 3,
        level_count: 3,
        secret_distribution: SecretKeyDistr::SparseTernary,
        error_distribution: ErrorDistribution::CenteredBinomial { eta: 10 },
    }
    .create_context()?;
    let backend = match std::env::args().nth(1).as_deref() {
        None => BgvBudgetBackend::Radix(DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        }),
        Some("--hybrid") => BgvBudgetBackend::hybrid(&context, 3, 50, 1)?,
        _ => return Err("expected no arguments or --hybrid".into()),
    };
    let mut one = context.new_plaintext();
    one.as_mut()[0] = 1;
    let one_bounds = BgvPlaintextBounds::try_new(
        context.parameters().poly_length(),
        context.parameters().plain_modulus(),
        one.as_ref(),
        PlaintextEmbedding::Centered,
    )?;
    let operations = [
        BgvCircuitOperation::PublicEncryption {
            embedding: PlaintextEmbedding::Centered,
        },
        BgvCircuitOperation::PublicEncryption {
            embedding: PlaintextEmbedding::Centered,
        },
        BgvCircuitOperation::Multiply { lhs: 0, rhs: 1 },
        BgvCircuitOperation::Multiply { lhs: 2, rhs: 2 },
        BgvCircuitOperation::DropPrime { input: 3 },
        BgvCircuitOperation::Automorphism {
            input: 4,
            exponent: 5,
        },
        BgvCircuitOperation::KeySwitch { input: 5 },
        BgvCircuitOperation::AddPlain {
            input: 6,
            plaintext: one_bounds,
        },
        BgvCircuitOperation::DropPrime { input: 7 },
    ];
    let plan = BgvCircuitPlan::try_new(&context, &operations, backend)?;
    for step in plan.steps() {
        println!(
            "node {}: level {}, factor {}, phase <= {}, recovery margin {}",
            step.node, step.level, step.correction_factor, step.phase_bound, step.margin
        );
    }
    println!(
        "Security estimation is separate: {} public input domain(s), not evaluated.",
        plan.security_inputs().len()
    );
    let mut rng = StdRng::seed_from_u64(0x10b6_c0ef);
    let alice = BgvClient::generate(&context, &mut rng);
    let mut bob = BgvClient::generate(&context, &mut rng);
    let public_key = alice.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let relin_key = alice.relinearization_key(
        0,
        plan.key_config(0).expect("planned level zero key"),
        &mut rng,
    )?;
    let auto_key = alice.automorphism_key(
        1,
        5,
        plan.key_config(1).expect("planned level one key"),
        &mut rng,
    )?;
    let switch_key = bob.key_switching_key(
        &alice,
        1,
        plan.key_config(1).expect("planned level one key"),
        &mut rng,
    )?;
    let mut multiplication = BgvMultiplication::try_new(&context, &relin_key)?;
    let mut auto = BgvAutomorphism::try_new(&context, &auto_key)?;
    let mut switch = BgvKeySwitcher::try_new(&context, &switch_key)?;
    let mut lower_evaluator = BgvEvaluator::new(&context, 1);
    let mut drop_first = BgvModulusSwitch::new(&context, 0);
    let mut drop_second = BgvModulusSwitch::new(&context, 1);
    let a = Polynomial((0..N).map(|i| (7 * i as u64 + 1) % P).collect::<Vec<_>>());
    let b = Polynomial((0..N).map(|i| (11 * i as u64 + 3) % P).collect::<Vec<_>>());
    let mut encrypted_a = context.new_ciphertext(0);
    let mut encrypted_b = context.new_ciphertext(0);
    let mut linear = context.new_ciphertext(0);
    let mut lower = context.new_ciphertext(1);
    let mut transformed = context.new_ciphertext(1);
    let mut switched = context.new_ciphertext(1);
    let mut lowest = context.new_ciphertext(2);

    encryptor.encrypt_centered_to(&a, &mut encrypted_a, &mut rng);
    encryptor.encrypt_centered_to(&b, &mut encrypted_b, &mut rng);
    multiplication.multiply_to(&encrypted_a, &encrypted_b, &mut linear);
    multiplication.square_assign(&mut linear);
    drop_first.switch_to(&linear, &mut lower);
    auto.apply_to(&lower, &mut transformed);
    switch.switch_to(&transformed, &mut switched);
    lower_evaluator.add_plain_assign(&mut switched, &one, PlaintextEmbedding::Centered);
    drop_second.switch_to(&switched, &mut lowest);
    let recovered = bob.decrypt(&lowest);

    let ab = product(a.as_ref(), b.as_ref());
    let squared = product(&ab, &ab);
    let mut expected = vec![0; N];
    for (degree, &value) in squared.iter().enumerate() {
        let target = 5 * degree % (2 * N);
        expected[target % N] = if target < N { value } else { (P - value) % P };
    }
    expected[0] = (expected[0] + 1) % P;
    assert_eq!(recovered.as_ref(), expected);
    println!(
        "Validated dense BGV (a*b)^2, relinearization, X->X^5, Alice->Bob switching, plaintext +1 and two prime drops (150-bit Q to 50-bit Q)."
    );
    Ok(())
}
