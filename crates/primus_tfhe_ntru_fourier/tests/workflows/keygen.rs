use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_integer::AsFrom;
use primus_modulus::PowOf2Modulus;
use primus_ntru::{BlockOccupancy, SecretKeyDistr};
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, CbsGadgetConfig, DecompositionConfig, TfheContext, TfheContextError,
};
use rand::{SeedableRng, rngs::StdRng};

use super::fixture::{config, decomposition, native_phase};

const NATIVE_TEST_N: usize = 64;
const NATIVE_TEST_SUPPORT: [usize; 2] = [0, 4];

fn native_control_fixture<T: TorusFftValue, Table: FftTable>() -> (
    TfheContext<T, Table, PowOf2Modulus<T>>,
    primus_tfhe_ntru_fourier::ClientKey<T>,
) {
    let mut config = config::<T>(BlindRotationMethod::Classic);
    config.bsk_poly_length = PolyLength::new(NATIVE_TEST_N);
    config.bsk_secret_distr = SecretKeyDistr::Gaussian {
        standard_deviation: 1.0,
    };
    let context = TfheContext::try_from_pbs_config(config).unwrap();
    let external = context.parameters().external_lwe();
    let mut input = vec![T::ZERO; external.dimension().get()];
    for index in NATIVE_TEST_SUPPORT {
        input[index] = T::ONE;
    }
    let mut ring = vec![T::SignedInteger::as_from(0i32); NATIVE_TEST_N];
    ring[0] = T::SignedInteger::as_from(1i32);
    ring[1] = T::SignedInteger::as_from(2i32);
    let client = primus_tfhe_ntru_fourier::ClientKey::new(
        primus_lwe::LweSecretKey::new(
            input,
            external.secret_key_distr(),
            external.cipher_modulus(),
        ),
        primus_ntru::NtruSecretKey::new(ring, config.bsk_secret_distr),
    );
    (context, client)
}

fn check_public_native_control_spectra<T: TorusFftValue, Table: FftTable>() {
    let (context, client) = native_control_fixture::<T, Table>();
    let parameters = context.parameters().blind_rotation();
    let n = NATIVE_TEST_N;
    let mut fft = context.new_fft_engine();
    let mut generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);

    // (1+2X) * sum((-2X)^k, k=0..N) = 1+2^N in the negacyclic ring.
    // N >= T::BITS, so the finite geometric series is the native inverse.
    let inverse = (0..n)
        .scan(T::ONE, |power, _| {
            let coefficient = power.cast_to_signed();
            *power = power.wrapping_mul(T::as_from(-2i32));
            Some(coefficient)
        })
        .collect::<Vec<_>>();
    let f = client.accumulator_ntru_secret_key().as_slice();
    let inverse_words = inverse
        .iter()
        .map(|&value| T::cast_from_signed(value))
        .collect::<Vec<_>>();
    let mut unit = vec![T::ZERO; n];
    unit[0] = T::ONE;
    assert_eq!(native_phase(&inverse_words, f), unit);

    let row_len = fft.fourier_length();
    let mut expected_spectrum = vec![Complex64::default(); row_len];
    let mut assert_spectra = |label: &str, values: &[Complex64], bit, lift, rng: &mut StdRng| {
        assert_eq!(values.len(), parameters.fourier_nlev_len());
        for (level, (actual, scalar)) in values
            .chunks_exact(row_len)
            .zip(parameters.basis().scalar_iter())
            .enumerate()
        {
            let mut noise = parameters
                .encryption_parameters()
                .noise_distribution()
                .sample_vec(n, rng);
            if lift && bit {
                noise[0] = noise[0].wrapping_add(scalar);
            }
            let mut coefficients = native_phase(&noise, &inverse);
            if !lift && bit {
                coefficients[0] = coefficients[0].wrapping_add(scalar);
            }
            fft.forward_as_torus(&coefficients, &mut expected_spectrum);
            assert_eq!(actual, expected_spectrum, "{label}, level {level}");
        }
    };

    let mut rng = StdRng::seed_from_u64(0x50C);
    let mut reference_rng = StdRng::seed_from_u64(0x50C);
    let key = generator
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap();
    let controls = key.classic_controls().unwrap();
    assert_spectra(
        "initializer",
        controls.initializer().as_ref(),
        true,
        true,
        &mut reference_rng,
    );
    let (first, negative) = controls.first_controls();
    assert!(negative.is_none());
    assert_spectra(
        "first control",
        first.as_ref(),
        true,
        true,
        &mut reference_rng,
    );
    let remaining = controls.remaining_controls();
    assert_eq!(remaining.len(), client.external_lwe_dimension() - 1);
    for (i, control) in remaining.enumerate() {
        assert_spectra(
            "NGSW control",
            control.as_ref(),
            NATIVE_TEST_SUPPORT.contains(&(i + 1)),
            false,
            &mut reference_rng,
        );
    }

    let mut rng = StdRng::seed_from_u64(0x11F7);
    let mut reference_rng = StdRng::seed_from_u64(0x11F7);
    let lift = generator
        .try_generate_public_lift_key(client.accumulator_ntru_secret_key(), parameters, &mut rng)
        .unwrap();
    assert_spectra("public lift", lift.as_ref(), true, true, &mut reference_rng);
}

#[test]
fn public_native_control_spectra() {
    #[cfg(feature = "rustfft")]
    {
        check_public_native_control_spectra::<u32, primus_fft::RustFftTable>();
        check_public_native_control_spectra::<u64, primus_fft::RustFftTable>();
    }
    #[cfg(feature = "tfhe-fft")]
    {
        check_public_native_control_spectra::<u32, primus_fft::TfheFftTable>();
        check_public_native_control_spectra::<u64, primus_fft::TfheFftTable>();
    }
}

/// Keygen rejects incompatible imports before sampling, including f that cannot
/// be represented at return q or inverted at Q. Error paths leave scratch reusable.
fn check_key_generation_boundaries<Table: FftTable>() {
    use primus_ntru::{NtruError, NtruSecretKey};
    use primus_tfhe_ntru_fourier::{ClientKey, KeyGenerationError, KeyGenerator, TfheKeyError};
    use rand::Rng;

    let mut config = config::<u32>(BlindRotationMethod::Classic);
    config.bsk_poly_length = PolyLength::new(64);
    let context = TfheContext::<u32, Table, _>::try_from_pbs_config(config)
        .unwrap()
        .try_with_circuit_bootstrap(CbsGadgetConfig {
            trace: decomposition(),
            scheme_switch: decomposition(),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        })
        .unwrap();
    let mut generator = KeyGenerator::new(&context);
    let mut rng = StdRng::seed_from_u64(115);
    let mut untouched = StdRng::seed_from_u64(115);
    let external = context.parameters().external_lwe();
    let imported = |dimension, constant| {
        let mut s = vec![0; dimension];
        s[..2].fill(1);
        let mut f = vec![0; 64];
        f[0] = constant;
        ClientKey::new(
            primus_lwe::LweSecretKey::new(
                s,
                external.secret_key_distr(),
                external.cipher_modulus(),
            ),
            NtruSecretKey::new(f, config.bsk_secret_distr),
        )
    };
    for (dimension, constant, expected) in [
        (
            7,
            1,
            KeyGenerationError::ClientKey(TfheKeyError::ExternalLweDimensionMismatch),
        ),
        (
            8,
            1 << 24,
            KeyGenerationError::ClientKey(TfheKeyError::AccumulatorSecretOutsideLweModulus),
        ),
        (
            8,
            0,
            KeyGenerationError::Ntru(NtruError::NonInvertibleSecretKey),
        ),
    ] {
        let client = imported(dimension, constant);
        if constant != 1 << 24 {
            assert_eq!(
                generator
                    .try_generate_blind_rotation_key(&client, &mut rng)
                    .err(),
                Some(expected.clone())
            );
        }
        assert_eq!(
            generator.try_generate_server_key(&client, &mut rng).err(),
            Some(expected.clone())
        );
        assert_eq!(
            generator
                .try_generate_circuit_bootstrap_server_key(&client, &mut rng)
                .err(),
            Some(expected)
        );
    }

    // A foreign lift is rejected before the joint path samples either client secret.
    let mut other_config = config;
    other_config.bsk_poly_length = PolyLength::new(32);
    let other = primus_tfhe_ntru_fourier::PbsParameters::try_from_config(other_config).unwrap();
    assert!(matches!(
        generator.try_generate_circuit_bootstrap_keys_with_public_lift(
            Some(other.blind_rotation()),
            &mut rng
        ),
        Err(KeyGenerationError::IncompatiblePublicLiftParameters)
    ));

    // Direct Block BR requires u64. Reject unsupported modes at context
    // construction, before allocating an FFT table or generating keys.
    let mut block_config = config;
    block_config.method = BlindRotationMethod::Block;
    block_config.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size: 2,
        occupancy: BlockOccupancy::AtMostOne,
    };
    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: decomposition(),
    };
    let block_cbs = primus_tfhe_ntru_fourier::CbsConfig {
        projection: primus_tfhe_ntru::NtruProjectionMethod::Separate,
        fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        pbs: block_config,
        gadget,
    };
    assert!(matches!(
        TfheContext::<u32, Table, _>::try_from_pbs_config(block_config),
        Err(TfheContextError::Block(
            primus_tfhe_ntru::BlockBootstrappingKeyError::UnsupportedFourierWordSize { bits: 32 },
        ))
    ));
    assert!(matches!(
        TfheContext::<u32, Table, _>::try_from_cbs_config(block_cbs),
        Err(TfheContextError::Block(
            primus_tfhe_ntru::BlockBootstrappingKeyError::UnsupportedFourierWordSize { bits: 32 },
        ))
    ));

    assert_eq!(rng.next_u64(), untouched.next_u64());

    // An invertible f outside return q is still valid for standalone BR.
    // Odd q+1 is a unit for the native torus as well as the NTT prime field.
    generator
        .try_generate_blind_rotation_key(&imported(8, (1 << 24) + 1), &mut rng)
        .unwrap();

    // Reuse the same generator with a unit f=1 and the declared binary weight.
    let client = imported(8, 1);
    let server = generator
        .try_generate_circuit_bootstrap_server_key(&client, &mut rng)
        .unwrap();
    context.evaluator(server.server_key()).unwrap();
    context.circuit_bootstrap_evaluator(&server).unwrap();
    context.one_hot_evaluator(&server).unwrap();
}

#[test]
fn key_generation_boundaries() {
    #[cfg(feature = "rustfft")]
    check_key_generation_boundaries::<primus_fft::RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check_key_generation_boundaries::<primus_fft::TfheFftTable>();
}
