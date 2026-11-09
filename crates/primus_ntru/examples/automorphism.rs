//! Coefficient/NTT key pair and an automorphism under the original secret.
//! Uses u64 coefficients at a small NTT prime; the modulus need not fill the word.
//! These are functional example parameters, not a security recommendation.
//! Run: `cargo run --release -p primus_ntru --example automorphism --features ntt`.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::PlaintextEmbedding;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruParameters, NttNtruAutomorphismKey, NttNtruAutomorphismWorkspace,
    NttNtruCiphertext, NttNtruGadgetEncryptWorkspace, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    const N: usize = 1024;
    let modulus = BarrettModulus::new(132_120_577u64);
    let poly_length = PolyLength::new(N);
    let table = U64NttTable::new(poly_length, modulus).unwrap();
    let parameters =
        NtruParameters::new(poly_length, 16, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let mut rng = StdRng::seed_from_u64(42);
    let (coeff_secret, secret) =
        NttNtruSecretKey::generate_pair(parameters.encryption_parameters(), &table, &mut rng)
            .unwrap();
    let key_parameters = NlevParameters::with_ntru_params(
        &parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(3),
            level_count: None,
        },
    );
    let auto = NttNtruAutomorphismKey::generate(
        3,
        &coeff_secret,
        &secret,
        &key_parameters,
        &table,
        &mut rng,
        &mut NttNtruGadgetEncryptWorkspace::new(parameters.poly_length()),
    );

    let mut message = Polynomial::<Vec<u64>>::zero(N);
    message.as_mut()[0] = 1;
    message.as_mut()[1] = 2;
    message.as_mut()[N / 2] = 3;
    let input = secret.encrypt_message(
        &message,
        &parameters,
        PlaintextEmbedding::Unsigned,
        &table,
        &mut rng,
    );
    let mut output = NttNtruCiphertext::<Vec<u64>>::zero(N);
    let mut workspace = NttNtruAutomorphismWorkspace::new(parameters.poly_length());
    auto.apply_ntt_to(&input, &mut output, modulus, &table, &mut workspace);

    // X^(3N/2) = -X^(N/2). The output is still under the original secret.
    let mut expected = vec![0; N];
    expected[0] = 1;
    expected[3] = 2;
    expected[N / 2] = 16 - 3;
    assert_eq!(
        secret
            .decrypt_message(&output, &parameters, &table)
            .as_ref(),
        expected
    );
}
