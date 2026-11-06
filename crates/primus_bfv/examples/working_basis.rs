//! Checked ordinary BFV square chain, with temporary internal modulus reduction.
use primus_bfv::{BfvClient, BfvLeveledKeyBackend, BfvLeveledParameters, BfvLeveledProfile};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const T: u64 = 65537;
    let context = BfvLeveledProfile::N16384Q240.create_context(T)?;
    let backend = if std::env::args().any(|x| x == "--radix") {
        BfvLeveledKeyBackend::Radix16
    } else {
        BfvLeveledKeyBackend::HybridAlpha1
    };
    let plan = BfvLeveledParameters::try_new(&context, 3, backend)?;
    let mut rng = StdRng::from_rng(&mut rand::rng());
    let mut client = BfvClient::generate(&context, &mut rng);
    let public_key = client.public_key(&mut rng);
    let mut encryptor = context.public_key_encryptor(&public_key)?;
    let keys = plan
        .steps()
        .iter()
        .map(|step| step.relinearization_key(&client, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let mut operations = plan
        .steps()
        .iter()
        .zip(&keys)
        .map(|(step, key)| step.prepare(key))
        .collect::<Result<Vec<_>, _>>()?;

    // External level stays zero throughout: (2+X) -> (2+X)^8.
    let mut message = Polynomial::<Vec<u64>>::zero(context.parameters().poly_length().get());
    message.as_mut()[..2].copy_from_slice(&[2, 1]);
    let mut ciphertext = context.new_ciphertext(0);
    encryptor.encrypt_centered_to(&message, &mut ciphertext, &mut rng);
    for operation in &mut operations {
        operation.square_assign(&mut ciphertext);
    }
    let mut recovered = Polynomial::<Vec<u64>>::zero(message.as_ref().len());
    client.decrypt_to(&ciphertext, &mut recovered);
    let coefficients = [256, 1024, 1792, 1792, 1120, 448, 112, 16, 1];
    assert_eq!(&recovered.as_ref()[..9], &coefficients);
    assert!(recovered.as_ref()[9..].iter().all(|&x| x == 0));
    println!("Three checked square layers recovered (2+X)^8 at external level zero.");
    Ok(())
}
