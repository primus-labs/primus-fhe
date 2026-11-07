//! A remote evaluator receives only public storage; the client keeps its secret.
//! Run: cargo run -p primus_bgv --example public_worker

use primus_bgv::evaluation::{BgvModulusSwitch, BgvMultiplication};
use primus_bgv::planning::BgvParameterRequest;
use primus_bgv::{BgvClient, BgvContext, ErrorDistribution, PublicObjectLimits, SecretKeyDistr};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Small arithmetic example; these parameters are not a security preset.
    let client_context = BgvParameterRequest {
        poly_length: PolyLength::new(32),
        plaintext_modulus: 193,
        ciphertext_prime_bits: 50,
        ciphertext_prime_count: 3,
        level_count: 3,
        secret_distribution: SecretKeyDistr::SparseTernary,
        error_distribution: ErrorDistribution::CenteredBinomial { eta: 1 },
    }
    .create_context()?;
    let mut client_rng = StdRng::seed_from_u64(2301);
    let mut client = BgvClient::generate(&client_context, &mut client_rng);
    let public_key = client.public_key(&mut client_rng);
    let relin = client.relinearization_key(
        0,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(16),
            level_count: None,
        },
        &mut client_rng,
    )?;
    let mut input = client_context.new_plaintext();
    input.as_mut()[..2].copy_from_slice(&[3, 2]);
    let encrypted = client_context
        .public_key_encryptor(&public_key)?
        .encrypt_centered(&input, &mut client_rng);

    // Authenticate these public bytes and their application identities in the
    // enclosing transport. The secret/client workspace is never serialized.
    let parameters = client_context.to_public_bytes();
    let public = client_context.export_public_key(&public_key)?;
    let evaluation = client_context.export_relinearization_key(&relin)?;
    let request = client_context.export_ciphertext(&encrypted, 0)?;

    let limits = PublicObjectLimits::default();
    let worker = BgvContext::from_public_bytes(&parameters, limits)?;
    let public_key = worker.import_public_key(&public, limits)?;
    let relin = worker.import_relinearization_key(&evaluation, limits)?;
    let encrypted = worker.import_ciphertext(&request, limits)?;
    let mut worker_rng = StdRng::seed_from_u64(2302);
    let mut multiplier = worker.new_plaintext();
    multiplier.as_mut()[..2].copy_from_slice(&[5, 1]);
    let other = worker
        .public_key_encryptor(&public_key)?
        .encrypt_centered(&multiplier, &mut worker_rng);
    let mut product = worker.new_ciphertext(0);
    BgvMultiplication::try_new(&worker, &relin)?.multiply_to(&encrypted, &other, &mut product);
    let mut lower = worker.new_ciphertext(1);
    BgvModulusSwitch::new(&worker, 0).switch_to(&product, &mut lower);
    let response = worker.export_ciphertext(&lower, 1)?;

    // Import rebinds to this client's context; factor survives the round trip.
    let received = client_context.import_ciphertext(&response, limits)?;
    let decoded = client.decrypt(&received);
    assert_eq!(&decoded.as_ref()[..3], &[15, 13, 2]);
    assert!(
        decoded.as_ref()[3..]
            .iter()
            .all(|&coefficient| coefficient == 0)
    );
    println!(
        "public worker recovered (3+2X)(5+X); level1 correction factor {}",
        received.correction_factor()
    );
    Ok(())
}
