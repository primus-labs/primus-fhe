//! Native u32/u64 encodings and full k*N secret sampling with reused workspaces.

use primus_encoding::PlaintextEmbedding;
use primus_fft::{FftEngine, FftTable, RustFftTable, TorusFftValue};
use primus_glwe::{
    FourierGlweCiphertext, FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace,
    FourierGlweSecretKey, GlweParameters, GlweSecretKey, SecretKeyDistr,
};
use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

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

    for secret_key_distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::gaussian(3.2),
        // A weight greater than N must be sampled over all k*N coefficients.
        SecretKeyDistr::fixed_hamming_weight_ternary(DIMENSION * POLY_LENGTH, POLY_LENGTH + 7),
    ] {
        let params = GlweParameters::new(
            GlweDimension::new(DIMENSION),
            PolyLength::new(POLY_LENGTH),
            T::try_from(PLAIN_MODULUS).unwrap(),
            NativeModulus::new(),
            secret_key_distr,
            0.7,
        );
        // Splitting layout from sampling state must preserve all k*N samples
        // and the RNG stream before transformation.
        let seed = rng.next_u64();
        rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        let expected_coefficients = GlweSecretKey::generate(
            params.size(),
            params.secret_key_sampler(),
            &mut expected_rng,
        );
        let (coefficients, secret_key) = FourierGlweSecretKey::generate_pair(
            params.size(),
            params.encryption_parameters(),
            &mut fft,
            &mut rng,
        );
        assert_eq!(coefficients.as_slice(), expected_coefficients.as_slice());
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
        let mut encrypt_workspace = FourierGlweEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
        let mut decrypt_workspace = FourierGlweDecryptWorkspace::new(PolyLength::new(POLY_LENGTH));

        let mut cipher = FourierGlweCiphertext::<Vec<_>>::zero(params.fourier_glwe_len());

        secret_key.encrypt_zeros_to(
            &mut cipher,
            params.encryption_parameters(),
            &mut fft,
            &mut rng,
            &mut encrypt_workspace,
        );
        assert_eq!(
            secret_key
                .decrypt_message(&cipher, &params, &mut fft, &mut decrypt_workspace)
                .as_ref(),
            vec![T::ZERO; POLY_LENGTH]
        );

        for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
            let mut encoded = vec![T::ZERO; POLY_LENGTH];
            params
                .plaintext_codec()
                .add_encode_slice_assign(&mut encoded, &messages, embedding);
            // Raw encoded encryption must equal ordinary encryption with the same
            // coins; this also checks that the codec is applied exactly once.
            let seed = rng.next_u64();
            rng = StdRng::seed_from_u64(seed);
            let mut expected_rng = StdRng::seed_from_u64(seed);
            let expected = secret_key.encrypt_message(
                &message,
                &params,
                embedding,
                &mut fft,
                &mut expected_rng,
                &mut encrypt_workspace,
            );
            secret_key.encrypt_encoded_to(
                &Polynomial::new(encoded),
                &mut cipher,
                params.encryption_parameters(),
                &mut fft,
                &mut rng,
                &mut encrypt_workspace,
            );
            assert_eq!(cipher.as_ref(), expected.as_ref());
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
            assert_eq!(
                secret_key
                    .decrypt_message(&cipher, &params, &mut fft, &mut decrypt_workspace)
                    .as_ref(),
                messages
            );
        }
    }
}

#[test]
fn fourier_glwe_secret_key_roundtrip_u32() {
    assert_roundtrip::<u32, RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    assert_roundtrip::<u32, primus_fft::TfheFftTable>();
}

#[test]
fn fourier_glwe_secret_key_roundtrip_u64() {
    assert_roundtrip::<u64, RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    assert_roundtrip::<u64, primus_fft::TfheFftTable>();
}
