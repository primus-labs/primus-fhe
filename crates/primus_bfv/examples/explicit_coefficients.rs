//! Reuse coefficient encryption outputs and erasing public/decryption workspaces.
//!
//! Run: cargo run -p primus_bfv --example explicit_coefficients
//! This small ring is an API example, not a security parameter preset.

use primus_bfv::{
    BfvCiphertext, BfvContext, BfvDecryptWorkspace, BfvParameters, BfvPublicKey,
    BfvPublicKeyEncryptor, BfvSecretKeyContext,
};
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parameters = BfvParameters::try_new(
        PolyLength::new(32),
        BarrettModulus::new(257),
        BarrettModulus::new(2_199_023_190_017),
        &[1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        3.2,
    )?;
    let context = BfvContext::try_new(parameters)?;
    let parameters = context.parameters();
    let table = context.table();
    let mut rng = rand::rng();
    let coefficient_key = GlweSecretKey::generate(
        parameters.size().glwe_size(),
        parameters.encryption_parameters().secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, table);
    let client = BfvSecretKeyContext::try_new(&key, &context)?;
    let public = BfvPublicKey::new(&client, &mut rng);
    let mut encryptor = BfvPublicKeyEncryptor::try_new(&public, &context)?;
    let mut workspace = BfvDecryptWorkspace::new(parameters);
    let mut ciphertext = BfvCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    let mut decoded = Polynomial::<Vec<u64>>::zero(parameters.poly_length().get());

    for value in [3, 256] {
        // Both unsigned and centered entries accept canonical values in [0,t).
        let message = Polynomial(vec![value; parameters.poly_length().get()]);
        client.encrypt_centered_to(&message, &mut ciphertext, &mut rng);
        client.decrypt_to(&ciphertext, &mut decoded, &mut workspace);
        assert_eq!(decoded, message);

        // Reuse ciphertext and ephemeral scratch, applying delta before the
        // c0's one NTT rather than materializing an encoded CRT polynomial.
        encryptor.encrypt_to(&message, &mut ciphertext, &mut rng);
        client.decrypt_to(&ciphertext, &mut decoded, &mut workspace);
        assert_eq!(decoded, message);
    }
    encryptor.zeroize();
    workspace.zeroize();
    client.decrypt_to(&ciphertext, &mut decoded, &mut workspace);
    assert!(decoded.as_ref().iter().all(|&value| value == 256));
    println!("BFV private/public coefficient encryption and workspace reuse verified");
    Ok(())
}
