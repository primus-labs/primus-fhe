use primus_fft::FftTable;
use primus_lattice::nlev::{NlevIter, NlevIterMut};
use primus_modulus::PowOf2Modulus;
use primus_ntru::{BlockOccupancy, LweDimension, SecretKeyDistr};
use primus_poly::PolynomialIter;
use primus_shape::PolyLength;
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, CbsGadgetConfig, ClientKey, KeyGenerationError, KeyGenerator, PbsConfig,
    TfheContext, TfheKeyError, key::BlindRotationKey,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

use super::{
    cbs::circuit_selection,
    fixture::{config, decomposition, native_phase},
    pbs::check_pbs_workflows,
};

/// The direct-block ordinary path consumes independent q/Q, unequal message
/// spaces, interleaved lanes, and CBS controls all the way back to LWE.
#[test]
fn u64_block_workflows() {
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        let mut pbs = config(BlindRotationMethod::Block);
        pbs.external_lwe.dimension = LweDimension::new(10);
        pbs.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 5,
            occupancy,
        };
        #[cfg(feature = "rustfft")]
        {
            check_pbs_workflows::<u64, primus_fft::RustFftTable>(pbs);
            circuit_selection::<u64, primus_fft::RustFftTable>(pbs, false);
        }
        #[cfg(feature = "tfhe-fft")]
        {
            check_pbs_workflows::<u64, primus_fft::TfheFftTable>(pbs);
            circuit_selection::<u64, primus_fft::TfheFftTable>(pbs, false);
        }
    }
}

/// Empty first blocks still carry NLEV lift rows; later blocks carry NGSW.
/// Check exact coefficient phases and reject malformed imported support pre-RNG.
fn check_block_coefficients<Table: FftTable>(occupancy: BlockOccupancy) {
    let mut pbs = config::<u64>(BlindRotationMethod::Block);
    pbs.external_lwe.dimension = LweDimension::new(6);
    pbs.external_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size: 3,
        occupancy,
    };
    pbs.bsk_poly_length = PolyLength::new(32);
    let gadget = CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: decomposition(),
    };
    let context = TfheContext::<u64, Table, _>::try_from_pbs_config(pbs)
        .unwrap()
        .try_with_circuit_bootstrap(gadget)
        .unwrap();
    let mut generator = KeyGenerator::new(&context);
    let mut f = vec![0i64; 32];
    f[..3].fill(1);
    let client = |support| {
        ClientKey::new(
            primus_lwe::LweSecretKey::new(
                support,
                pbs.external_lwe.secret_key_distr,
                context.parameters().external_lwe().cipher_modulus(),
            ),
            primus_ntru::NtruSecretKey::new(f.clone(), pbs.bsk_secret_distr),
        )
    };
    let mut rng = StdRng::seed_from_u64(0xB30);
    let mut untouched = StdRng::seed_from_u64(0xB30);
    let invalid = client(vec![1, 1, 0, 0, 0, 0]);
    let expected = Some(KeyGenerationError::ClientKey(
        TfheKeyError::InvalidClientSecretKeyBlock,
    ));
    assert_eq!(
        generator
            .try_generate_blind_rotation_key(&invalid, &mut rng)
            .err(),
        expected
    );
    assert_eq!(
        generator.try_generate_server_key(&invalid, &mut rng).err(),
        expected
    );
    assert_eq!(
        generator
            .try_generate_circuit_bootstrap_server_key(&invalid, &mut rng)
            .err(),
        expected
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());

    let has_dummy = occupancy == BlockOccupancy::AtMostOne;
    let supports = if has_dummy {
        [vec![0, 0, 0, 0, 1, 0], vec![0; 6]]
    } else {
        [vec![1, 0, 0, 0, 1, 0], vec![0, 0, 1, 0, 0, 1]]
    };
    for support in supports {
        let client = client(support.clone());
        let key = generator
            .try_generate_blind_rotation_key(&client, &mut rng)
            .unwrap();
        assert_control_phases(&context, &key, &support, &f, has_dummy);
    }

    let client = client(vec![1, 0, 0, 0, 1, 0]);
    check_block_precision(&context, &mut generator, &client, pbs, gadget, occupancy);
}

/// First-block NLEV phases encode constants. Later NGSW phases encode f.
fn assert_control_phases<Table: FftTable>(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    key: &BlindRotationKey<u64>,
    support: &[u64],
    f: &[i64],
    has_dummy: bool,
) {
    let control_len = context.parameters().blind_rotation().nlev_len();
    let block = key.block_bootstrapping_key().unwrap();
    assert!(key.classic_controls().is_none());
    assert_eq!(block.blocks().len(), 2);
    for (block_index, (range, controls, dummy)) in block.blocks().enumerate() {
        let occupied = support[range.clone()].iter().copied().sum::<u64>();
        let rows = NlevIter::new(controls, control_len).chain(NlevIter::new(dummy, control_len));
        for (row, bit) in rows.zip(
            support[range]
                .iter()
                .copied()
                .chain(has_dummy.then_some(1 - occupied)),
        ) {
            for (polynomial, scalar) in PolynomialIter::new(row.as_ref(), 32)
                .zip(context.parameters().blind_rotation().basis().scalar_iter())
            {
                let phase = native_phase(polynomial.as_ref(), f);
                for (i, actual) in phase.into_iter().enumerate() {
                    let message = if block_index == 0 {
                        u64::from(i == 0)
                    } else {
                        f[i] as u64
                    };
                    let expected = scalar.wrapping_mul(bit).wrapping_mul(message);
                    // sigma=0.7 has truncated support below this fixed margin.
                    // A Fourier ciphertext round trip has far larger phase error.
                    assert!(
                        actual
                            .wrapping_sub(expected)
                            .min(expected.wrapping_sub(actual))
                            <= 16
                    );
                }
            }
        }
    }
}

/// Split BR preserves the exact coefficient payload and encryption coins,
/// while resource binding still distinguishes the requested Fourier precision.
fn check_block_precision<Table: FftTable>(
    context: &TfheContext<u64, Table, PowOf2Modulus<u64>>,
    generator: &mut KeyGenerator<'_, u64, Table, PowOf2Modulus<u64>>,
    client: &ClientKey<u64>,
    pbs: PbsConfig<u64, PowOf2Modulus<u64>>,
    gadget: CbsGadgetConfig,
    occupancy: BlockOccupancy,
) {
    // Precision changes only the online transform, not the exact coefficient
    // material or fresh encryption coins. Equality here is a representation
    // regression check; it does not certify Fourier error or a parameter DFR.
    let split_br = primus_tfhe_ntru_fourier::CbsConfig {
        pbs,
        gadget,
        projection: primus_tfhe_ntru_fourier::NtruProjectionMethod::Separate,
        fourier_precision: primus_tfhe_ntru_fourier::FourierCbsPrecision {
            blind_rotation: primus_tfhe_ntru_fourier::FourierPrecision::Split { low_bits: 40 },
            trace: primus_tfhe_ntru_fourier::FourierPrecision::Ordinary,
            scheme_switch: primus_tfhe_ntru_fourier::FourierPrecision::Ordinary,
        },
    };
    let control_len = context.parameters().blind_rotation().nlev_len();
    let split_context = TfheContext::<u64, Table, _>::try_from_cbs_config(split_br).unwrap();
    let mut split_generator = KeyGenerator::new(&split_context);
    let mut ordinary_rng = StdRng::seed_from_u64(0xB3C);
    let mut split_rng = StdRng::seed_from_u64(0xB3C);
    let ordinary_key = generator
        .try_generate_blind_rotation_key(client, &mut ordinary_rng)
        .unwrap();
    let split_key = split_generator
        .try_generate_blind_rotation_key(client, &mut split_rng)
        .unwrap();
    assert_eq!(
        ordinary_key.block_bootstrapping_key().unwrap().as_slice(),
        split_key.block_bootstrapping_key().unwrap().as_slice(),
    );
    let next_ordinary = ordinary_rng.next_u64();
    assert_eq!(next_ordinary, split_rng.next_u64());
    if occupancy == BlockOccupancy::ExactlyOne {
        let exact = primus_ntru::split::NativeNtruGadgetGenerator::try_new(
            client.accumulator_ntru_secret_key(),
        )
        .unwrap();
        let mut reference = vec![0; 6 * control_len];
        let mut replay = StdRng::seed_from_u64(0xB3C);
        for (i, (&bit, coefficients)) in client
            .external_lwe_secret_key()
            .as_ref()
            .iter()
            .zip(NlevIterMut::new(&mut reference, control_len))
            .enumerate()
        {
            exact.encrypt_bit_coeff_to(
                bit == 1,
                i < 3,
                coefficients,
                context.parameters().blind_rotation(),
                &mut replay,
            );
        }
        assert_eq!(
            ordinary_key.block_bootstrapping_key().unwrap().as_slice(),
            reference
        );
        assert_eq!(replay.next_u64(), next_ordinary);
    }

    // Identical coefficient payloads still bind to distinct online precision.
    // Bootstrap resources validate that binding before allocating any buffers.
    use primus_tfhe_ntru_fourier::{
        FourierPrecision, TfheEvaluationError, bootstrap::BootstrapResources,
    };
    assert_eq!(ordinary_key.precision(), FourierPrecision::Ordinary);
    assert_eq!(
        split_key.precision(),
        FourierPrecision::Split { low_bits: 40 }
    );
    assert!(BootstrapResources::try_new(context, &ordinary_key).is_ok());
    assert!(BootstrapResources::try_new(&split_context, &split_key).is_ok());
    assert!(matches!(
        BootstrapResources::try_new(context, &split_key),
        Err(TfheEvaluationError::IncompatibleBlindRotationKey)
    ));
    assert!(matches!(
        BootstrapResources::try_new(&split_context, &ordinary_key),
        Err(TfheEvaluationError::IncompatibleBlindRotationKey)
    ));
    let mut other_split = split_br;
    other_split.fourier_precision.blind_rotation = FourierPrecision::Split { low_bits: 35 };
    let other_split = TfheContext::<u64, Table, _>::try_from_cbs_config(other_split).unwrap();
    assert!(matches!(
        BootstrapResources::try_new(&other_split, &split_key),
        Err(TfheEvaluationError::IncompatibleBlindRotationKey)
    ));

    // Split BR requires binary controls. Classic ternary uses ordinary BR.
    let mut unsupported = split_br;
    unsupported.pbs.method = BlindRotationMethod::Classic;
    unsupported.pbs.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    assert!(matches!(
        TfheContext::<u64, Table, _>::try_from_cbs_config(unsupported),
        Err(primus_tfhe_ntru_fourier::TfheContextError::UnsupportedSplitBlindRotation)
    ));
}

#[test]
fn block_coefficient_phases_and_key_boundaries() {
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        #[cfg(feature = "rustfft")]
        check_block_coefficients::<primus_fft::RustFftTable>(occupancy);
        #[cfg(feature = "tfhe-fft")]
        check_block_coefficients::<primus_fft::TfheFftTable>(occupancy);
    }
}
