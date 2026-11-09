//! Independent NTRU key switching and validation before output mutation.

use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_encoding::PlaintextEmbedding;
use primus_shape::PolyLength;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruCiphertext, NtruParameters, NtruSecretKey, NttNtruExternalProductWorkspace,
    NttNtruGadgetEncryptWorkspace, NttNtruKeySwitchingKey, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{NttTable, UintNttTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

// Functional ring size; keep the original word widths, moduli and decomposition.
const POLY_LENGTH: usize = 64;
const PLAIN_MODULUS: u32 = 16;
const EXPLICIT_MODULUS: u32 = 132_120_577;

fn message() -> Vec<u32> {
    (0..POLY_LENGTH)
        .map(|index| (3 * index as u32 + 1) % PLAIN_MODULUS)
        .collect()
}

#[test]
fn ntt_key_switch_preserves_plaintext() {
    let mut rng = StdRng::seed_from_u64(0x4e54_5452_554b_534b);
    let modulus = BarrettModulus::new(EXPLICIT_MODULUS);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let parameters = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let key_switching = NlevParameters::with_ntru_params(
        &parameters,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(9),
            level_count: None,
        },
    );
    let (input_coefficient_key, input_key) =
        NttNtruSecretKey::generate_pair(parameters.encryption_parameters(), &ntt, &mut rng)
            .unwrap();
    let (output_coefficient_key, output_key) =
        NttNtruSecretKey::generate_pair(parameters.encryption_parameters(), &ntt, &mut rng)
            .unwrap();
    assert_ne!(
        input_coefficient_key.as_slice(),
        output_coefficient_key.as_slice()
    );

    let mut gadget_workspace = NttNtruGadgetEncryptWorkspace::new(PolyLength::new(POLY_LENGTH));
    let switching_key = NttNtruKeySwitchingKey::generate(
        &input_coefficient_key,
        &output_key,
        &key_switching,
        &ntt,
        &mut rng,
        &mut gadget_workspace,
    );

    let message = message();
    let input = input_key
        .encrypt_message(
            &Polynomial::new(message.as_slice()),
            &parameters,
            PlaintextEmbedding::Unsigned,
            &ntt,
            &mut rng,
        )
        .into_coeff_form(&ntt);
    let mut external_product = NttNtruExternalProductWorkspace::new(PolyLength::new(POLY_LENGTH));
    // The borrowed ciphertext occupies only the middle of the caller's buffer.
    let mut storage = vec![7; POLY_LENGTH + 2];
    let mut switched = NtruCiphertext::new(&mut storage[1..=POLY_LENGTH]);
    switching_key.key_switch_to(
        &input.as_view(),
        &mut switched,
        modulus,
        &ntt,
        &mut external_product,
    );
    let switched = switched.into_ntt_form(&ntt);

    assert_eq!(
        output_key
            .decrypt_message(&switched, &parameters, &ntt)
            .as_ref(),
        message
    );
    assert_eq!((storage[0], storage[POLY_LENGTH + 1]), (7, 7));
}

fn unit_key() -> NtruSecretKey<u32> {
    let mut coefficients = vec![0; POLY_LENGTH];
    coefficients[0] = 1;
    NtruSecretKey::new(coefficients, SecretKeyDistr::UniformBinary)
}

#[test]
fn ntt_key_switch_rejects_mismatched_resources_before_writing() {
    let modulus = BarrettModulus::new(EXPLICIT_MODULUS);
    let other_modulus = BarrettModulus::new(998_244_353);
    let ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let short_ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH / 2), modulus).unwrap();
    let other_ntt = UintNttTable::new(PolyLength::new(POLY_LENGTH), other_modulus).unwrap();
    let params = NtruParameters::new(
        PolyLength::new(POLY_LENGTH),
        PLAIN_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let params = NlevParameters::with_ntru_params(
        &params,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(9),
            level_count: None,
        },
    );
    let coeff_key = unit_key();
    let key = NttNtruSecretKey::try_from_coeff_secret_key(&coeff_key, modulus, &ntt).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4e54_545f_424f_554e);
    let switching_key = NttNtruKeySwitchingKey::generate(
        &coeff_key,
        &key,
        &params,
        &ntt,
        &mut rng,
        &mut NttNtruGadgetEncryptWorkspace::new(PolyLength::new(POLY_LENGTH)),
    );

    for (name, input_len, output_len, scratch_len, modulus, table) in [
        (
            "input",
            POLY_LENGTH / 2,
            POLY_LENGTH,
            POLY_LENGTH,
            modulus,
            &ntt,
        ),
        (
            "output",
            POLY_LENGTH,
            POLY_LENGTH / 2,
            POLY_LENGTH,
            modulus,
            &ntt,
        ),
        (
            "scratch",
            POLY_LENGTH,
            POLY_LENGTH,
            POLY_LENGTH / 2,
            modulus,
            &ntt,
        ),
        (
            "table length",
            POLY_LENGTH,
            POLY_LENGTH,
            POLY_LENGTH,
            modulus,
            &short_ntt,
        ),
        (
            "arithmetic modulus",
            POLY_LENGTH,
            POLY_LENGTH,
            POLY_LENGTH,
            other_modulus,
            &ntt,
        ),
        (
            "table modulus",
            POLY_LENGTH,
            POLY_LENGTH,
            POLY_LENGTH,
            modulus,
            &other_ntt,
        ),
    ] {
        let input = NtruCiphertext::<Vec<u32>>::zero(input_len);
        let mut output = NtruCiphertext::new(vec![7; output_len]);
        let mut scratch = NttNtruExternalProductWorkspace::new(PolyLength::new(scratch_len));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                switching_key.key_switch_to(&input, &mut output, modulus, table, &mut scratch);
            }))
            .is_err(),
            "{name}"
        );
        assert_eq!(output.as_ref(), vec![7; output_len], "{name}");
    }
}
