//! Native u32/u64 encodings and full k*N secret sampling with reused workspaces.

#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

use num_traits::ConstZero;
use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::FourierGlweEncryptor;
use primus_glwe::{
    FourierGlweCiphertext, FourierGlweDecryptWorkspace, FourierGlweSecretKey, GlweParameters,
    GlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const DIMENSION: usize = 2;
// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;
const PLAIN_MODULUS: usize = 16;

fn assert_roundtrip<T, Table>()
where
    T: FheUint + TorusFftValue,
    Table: FftTable,
{
    let table = Table::new(PolyLength::new(POLY_LENGTH));
    let mut fft = FftEngine::new(&table);
    let mut rng = StdRng::seed_from_u64(42);
    let messages: Vec<T> = (0..POLY_LENGTH)
        .map(|index| T::try_from(index % PLAIN_MODULUS).unwrap())
        .collect();
    let message = Polynomial::new(messages.clone());

    // A weight greater than N exercises all k*N coefficients, including the second mask.
    let weight = POLY_LENGTH + 7;
    let params = GlweParameters::new(
        GlweDimension::new(DIMENSION),
        PolyLength::new(POLY_LENGTH),
        T::try_from(PLAIN_MODULUS).unwrap(),
        NativeModulus::new(),
        SecretKeyDistr::fixed_hamming_weight_ternary(DIMENSION * POLY_LENGTH, weight),
        0.7,
    );
    let coefficients = GlweSecretKey::generate(
        params.size(),
        params.encryption_parameters().secret_key_sampler(),
        &mut rng,
    );
    assert_eq!(
        coefficients
            .as_slice()
            .iter()
            .filter(|&&s| s != T::SignedInteger::ZERO)
            .count(),
        weight,
    );
    let decryptor = FourierGlweSecretKey::from_coeff_secret_key(&coefficients, &mut fft);
    let mut encryptor =
        FourierGlweEncryptor::try_new(&coefficients, params.encryption_parameters()).unwrap();
    let mut workspace = FourierGlweDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let mut ciphertext = FourierGlweCiphertext::<Vec<_>>::zero(params.fourier_glwe_len());
    let mut output = Polynomial::new(vec![T::MAX; POLY_LENGTH]);

    // The exact coefficient oracle covers raw/encoded ciphertext equality and RNG.
    // Here reuse the decryption workspace across both embeddings and a zero message.
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        encryptor.encrypt_message_to(
            &message,
            &mut ciphertext,
            &params,
            embedding,
            &mut fft,
            &mut rng,
        );
        decryptor.decrypt_message_to(&ciphertext, &mut output, &params, &mut fft, &mut workspace);
        assert_eq!(output.as_ref(), messages);
    }
    encryptor.encrypt_zeros_to(
        &mut ciphertext,
        params.encryption_parameters(),
        &mut fft,
        &mut rng,
    );
    decryptor.decrypt_message_to(&ciphertext, &mut output, &params, &mut fft, &mut workspace);
    assert_eq!(output.as_ref(), vec![T::ZERO; POLY_LENGTH]);
}

#[test]
fn fourier_glwe_secret_key_roundtrip_u32() {
    #[cfg(feature = "rustfft")]
    assert_roundtrip::<u32, primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    assert_roundtrip::<u32, primus_fft::TfheFftTable>();
}

#[test]
fn fourier_glwe_secret_key_roundtrip_u64() {
    #[cfg(feature = "rustfft")]
    assert_roundtrip::<u64, primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    assert_roundtrip::<u64, primus_fft::TfheFftTable>();
}
