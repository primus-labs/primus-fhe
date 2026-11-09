//! Public encryption for unsigned and centered messages using a shared workspace.

use primus_encoding::PlaintextEmbedding;
use primus_glwe::{
    GlweEncryptionParameters, GlweParameters, NttGlweCiphertext, NttGlwePublicEncryptWorkspace,
    NttGlwePublicKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

const DIMENSION: usize = 2;
// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 32;
const PLAIN_MODULUS: u64 = 256;
const CIPHER_MODULUS: u64 = 1_125_899_906_826_241;

#[test]
fn public_key_encoding_modes_reuse_workspace() {
    let modulus = BarrettModulus::new(CIPHER_MODULUS);
    let params = GlweParameters::new(
        GlweDimension::new(DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let table = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, secret_key) = NttGlweSecretKey::generate_pair(
        params.size(),
        params.encryption_parameters(),
        &table,
        &mut rng,
    );
    let public_key = NttGlwePublicKey::generate(
        &secret_key,
        params.encryption_parameters(),
        &table,
        &mut rng,
    );
    let public_key_view = NttGlwePublicKey::from(NttGlweCiphertext::new(public_key.as_ref()));
    // Keep the centered sign boundary and endpoints even when N is smaller than t.
    let message = Polynomial::new(
        (0..POLY_LENGTH)
            .map(|index| {
                [
                    0,
                    1,
                    PLAIN_MODULUS / 2 - 1,
                    PLAIN_MODULUS / 2,
                    PLAIN_MODULUS - 1,
                ][index % 5]
            })
            .collect::<Vec<_>>(),
    );

    let mut workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    // The same coins must yield the same ciphertext for explicit encoding and
    // the corresponding plaintext embedding, even after reusing the workspace.
    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let seed = rng.next_u64();
        let mut actual_rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        let mut fresh_workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
        let expected = public_key.encrypt_message(
            &message,
            &params,
            embedding,
            &table,
            &mut expected_rng,
            &mut fresh_workspace,
        );
        let mut encoded = Polynomial::new(vec![0; POLY_LENGTH]);
        params.plaintext_codec().add_encode_slice_assign(
            encoded.as_mut(),
            message.as_ref(),
            embedding,
        );
        let mut ciphertext: NttGlweCiphertext<Vec<u64>> =
            NttGlweCiphertext::zero(params.glwe_len());
        // Borrowed key/message/output follow the same encoding and RNG oracle.
        public_key_view.encrypt_encoded_to(
            &encoded.as_view(),
            &mut ciphertext.as_mut_view(),
            params.encryption_parameters(),
            &table,
            &mut actual_rng,
            &mut workspace,
        );
        assert_eq!(ciphertext.as_ref(), expected.as_ref());
        assert_eq!(actual_rng.next_u64(), expected_rng.next_u64());
        assert_eq!(
            secret_key
                .decrypt_message(&ciphertext, &params, &table)
                .as_ref(),
            message.as_ref()
        );
    }

    let encrypted_zero = public_key.encrypt_zeros(
        params.encryption_parameters(),
        &table,
        &mut rng,
        &mut workspace,
    );
    assert_eq!(
        secret_key
            .decrypt_message(&encrypted_zero, &params, &table)
            .as_ref(),
        vec![0; POLY_LENGTH]
    );
}

// Raw imported public keys have no size metadata. Reject incomplete masks/body
// and mismatched output before the shared encryption kernel consumes randomness.
#[test]
fn raw_public_encryption_checks_complete_key_and_output_layouts() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let n = POLY_LENGTH;
    let modulus = BarrettModulus::new(CIPHER_MODULUS);
    let inner = GlweEncryptionParameters::new(modulus, SecretKeyDistr::UniformBinary, 0.7);
    let table = UintNttTable::new(PolyLength::new(n), modulus).unwrap();
    let mut workspace = NttGlwePublicEncryptWorkspace::new(PolyLength::new(n));
    let encoded = Polynomial::new(vec![1; n]);
    for (key_len, output_len) in [
        (0, 2 * n),
        (n, n),
        (2 * n - 1, 2 * n - 1),
        (2 * n + 1, 2 * n + 1),
        (2 * n, 3 * n),
    ] {
        let key = NttGlwePublicKey::from(NttGlweCiphertext::new(vec![1; key_len]));
        for zero in [false, true] {
            let mut output = NttGlweCiphertext::new(vec![7; output_len]);
            let mut rng = StdRng::seed_from_u64(43);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if zero {
                        key.encrypt_zeros_to(&mut output, &inner, &table, &mut rng, &mut workspace);
                    } else {
                        key.encrypt_encoded_to(
                            &encoded,
                            &mut output,
                            &inner,
                            &table,
                            &mut rng,
                            &mut workspace,
                        );
                    }
                }))
                .is_err()
            );
            assert_eq!(output.as_ref(), vec![7; output_len]);
            assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());
        }
    }
}
