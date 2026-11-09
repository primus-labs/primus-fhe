//! Minimal LWE encryption and decryption workflow.
//!
//! Run with `cargo run -p primus_lwe --example basic`.
//! The small dimension keeps the example fast and is not a security recommendation.

use primus_encoding::PlaintextEmbedding;
use primus_lattice::LweDimension;
use primus_lattice::lwe::{Lwe, LweIter};
use primus_lwe::{LweParameters, LwePublicKey, LweSecretKey, SecretKeyDistr};
use primus_modulus::NativeModulus;

const LWE_DIMENSION: usize = 64;
const PLAINTEXT_MODULUS: u64 = 4;

fn main() {
    let parameters = LweParameters::new(
        LweDimension::new(LWE_DIMENSION),
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let mut rng = rand::rng();
    let secret_key = LweSecretKey::generate(parameters.encryption_parameters(), &mut rng);

    // Applications convert message types before encryption and after decryption.
    let message_byte = 3u8;
    let message = u64::from(message_byte);
    let ciphertext =
        secret_key.encrypt_message(message, &parameters, PlaintextEmbedding::Unsigned, &mut rng);
    let decrypted = secret_key.decrypt_message(&ciphertext, &parameters);
    let decrypted_byte = u8::try_from(decrypted).unwrap();
    assert_eq!(decrypted_byte, message_byte);

    // Reuse caller-owned storage; decryption accepts the borrowed ciphertext too.
    let mut storage = [0u64; LWE_DIMENSION + 1];
    let mut output = Lwe::new(&mut storage[..]);
    secret_key.encrypt_message_to(
        message,
        &mut output,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &mut rng,
    );
    assert_eq!(secret_key.decrypt_message(&output, &parameters), message);

    // The public key can be given to a sender who does not have the secret.
    // Public-key output noise grows with the secret and ephemeral vector norms;
    // these demonstration parameters are not a security recommendation.
    let public_key = LwePublicKey::generate(
        secret_key.as_view(),
        parameters.dimension(),
        parameters.cipher_modulus(),
        parameters.cipher_modulus_uniform_distr(),
        parameters.noise_distribution(),
        &mut rng,
    );
    let ciphertext =
        public_key.encrypt_message(message, &parameters, PlaintextEmbedding::Unsigned, &mut rng);
    assert_eq!(
        secret_key.decrypt_message(&ciphertext, &parameters),
        message
    );
    public_key.encrypt_message_to(
        message,
        &mut output,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &mut rng,
    );
    assert_eq!(secret_key.decrypt_message(&output, &parameters), message);

    // Independent samples share one allocation and remain usable individually.
    let messages = [0u64, 1, 2, 3];
    let batch = public_key.encrypt_message_batch(
        &messages,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &mut rng,
    );
    assert_eq!(
        secret_key.decrypt_message_batch(&batch, &parameters),
        messages
    );
    for (ciphertext, &message) in LweIter::new(&batch, ciphertext.lwe_len()).zip(&messages) {
        assert_eq!(
            secret_key.decrypt_message(&ciphertext, &parameters),
            message
        );
    }
    let mut storage = [0u64; 4 * (LWE_DIMENSION + 1)];
    secret_key.encrypt_message_batch_to(
        &messages,
        &mut storage,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &mut rng,
    );
    let mut decoded = [0u64; 4];
    secret_key.decrypt_message_batch_to(&storage, &mut decoded, &parameters);
    assert_eq!(decoded, messages);
}
