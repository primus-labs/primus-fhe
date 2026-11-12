//! Block blind-rotation arithmetic against independent phase oracles.

use primus_encoding::phase_error_magnitude;
use primus_glwe::{BlockOccupancy, GlweDimension, NttGlweSecretKey, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::ReduceNeg;
use primus_shape::PolyLength;
use primus_tfhe_glwe_ntt::{BlindRotationMethod, ModulusConfig, PbsOrder, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

use super::parameters::{config, two_domain_config};

/// Direct blocks retain the single-input ciphertext, including each lane's
/// canonical reduction and odd/even final-buffer placement. The layouts cover
/// 16/8/4/2/1 lane groups and both sides of the four-source word bound.
#[test]
fn block_batch_matches_single_inputs() {
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        for (q, width, blocks) in [
            (67_104_769u32, 3, 3),
            (998_244_353, 5, 2),
            (67_104_769, 7, 3),
        ] {
            check_block_batch::<u32, U32NttTable, 4>(q, width, blocks, occupancy);
            check_block_batch::<u32, U32NttTable, 16>(q, width, blocks, occupancy);
        }
        // rank=2 and full base-16 decomposition give 3,744/4,608 coefficients
        // for Q50/Q61: both exceed one u64 16 KiB tile (2,048 coefficients).
        // Q61 has insufficient headroom for four unreduced sources; Q16 fits one tile.
        for (q, width, blocks) in [
            (65_537u64, 3, 2),
            (1_125_899_906_826_241, 5, 3),
            (2_305_843_009_213_692_737, 7, 2),
        ] {
            check_block_batch::<u64, U64NttTable, 4>(q, width, blocks, occupancy);
            check_block_batch::<u64, U64NttTable, 16>(q, width, blocks, occupancy);
        }
    }
}

fn check_block_batch<T: FheUint, Table: MonomialNttTable<ValueT = T>, const LANES: usize>(
    q: T,
    block_size: usize,
    block_count: usize,
    occupancy: BlockOccupancy,
) {
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_ntt::{
        ClientKey, KeyGenerator,
        block::{BlockGlweBlindRotationBatchWorkspace, BlockGlweBlindRotationWorkspace},
        key::BlindRotationKey,
    };

    let n = 32;
    let mut config = config::<T>(BlindRotationMethod::Block);
    config.small_lwe.dimension = LweDimension::new(block_size * block_count);
    config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
        block_size,
        occupancy,
    };
    config.small_lwe.cipher_modulus = ModulusConfig::Explicit(T::as_from(2 * n));
    config.bsk_poly_length = PolyLength::new(n);
    config.ring_modulus = ModulusConfig::Explicit(q);
    let context = TfheContext::<T, Table>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(561 + block_size as u64);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let BlindRotationKey::Block(key) = KeyGenerator::new(&context)
        .try_generate_blind_rotation_key(&client, &mut rng)
        .unwrap()
    else {
        panic!("expected direct block key");
    };
    let mut single = BlockGlweBlindRotationWorkspace::new(&key);
    let mut batch = BlockGlweBlindRotationBatchWorkspace::<T, LANES>::new(&key);
    let rotation =
        RotationModulusSwitch::new(context.parameters().small_lwe().cipher_modulus(), 2 * n, 1);
    let inputs: Vec<_> = (0..17)
        .map(|lane| {
            let mut input = context.allocate_lwe_ciphertext();
            for (i, value) in input.as_mut().iter_mut().enumerate() {
                // Exact exponents include zero, the negacyclic sign boundary,
                // and the last residue; neighbouring lanes have different rotations.
                *value = T::as_from([0, n, 2 * n - 1, 13][(i + lane) % 4]);
            }
            *input.b_mut() = T::as_from((5 * lane) & (2 * n - 1));
            input
        })
        .collect();
    let lut = Polynomial::new((0..n).map(|i| T::as_from(i * 37)).collect::<Vec<_>>());
    let mut expected = vec![context.allocate_accumulator_ciphertext(); inputs.len()];
    let mut actual = expected.clone();
    for (input, output) in inputs.iter().zip(&mut expected) {
        single.blind_rotate_lookup_table_to(&key, input, &lut, &rotation, output, context.table());
    }
    // Ascending and descending sizes reuse dirty lanes after full and partial
    // batches, covering every 16/8/4/2/1 tail and no-write zero-length call.
    for count in (0..=17).chain((0..=17).rev()) {
        for output in &mut actual {
            output.as_mut().fill(T::ONE);
        }
        batch.blind_rotate_lookup_table_many_to(
            &key,
            &inputs[..count],
            &lut,
            &rotation,
            &mut actual[..count],
            context.table(),
        );
        for (got, want) in actual[..count].iter().zip(&expected) {
            assert_eq!(
                got.as_ref(),
                want.as_ref(),
                "capacity={LANES}, block_size={block_size}, count={count}"
            );
        }
        assert!(
            actual[count..]
                .iter()
                .all(|ct| ct.as_ref().iter().all(|&x| x == T::ONE))
        );
    }
    if T::BITS == 64 && block_size == 5 {
        // Cache capacity is optional: a workspace allocated for narrower blocks
        // has the same numerical layout, but no four-rotation descriptors. It
        // must still evaluate this key correctly using on-demand addressing.
        let mut narrow_config = config;
        narrow_config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy: if occupancy == BlockOccupancy::AtMostOne {
                BlockOccupancy::ExactlyOne
            } else {
                BlockOccupancy::AtMostOne
            },
        };
        let narrow_context = TfheContext::<T, Table>::try_from_pbs_config(narrow_config).unwrap();
        let narrow_client = ClientKey::generate(narrow_context.parameters(), &mut rng);
        let BlindRotationKey::Block(narrow_key) = KeyGenerator::new(&narrow_context)
            .try_generate_blind_rotation_key(&narrow_client, &mut rng)
            .unwrap()
        else {
            panic!("expected narrower block key");
        };
        let mut narrow = BlockGlweBlindRotationBatchWorkspace::<T, LANES>::new(&narrow_key);
        narrow.blind_rotate_lookup_table_many_to(
            &key,
            &inputs,
            &lut,
            &rotation,
            &mut actual,
            context.table(),
        );
        for (got, want) in actual.iter().zip(&expected) {
            assert_eq!(got.as_ref(), want.as_ref());
        }
    }
    // Check transactional layout rejection once, using a late malformed entry
    // so validation cannot be interleaved with writes to preceding lanes.
    if T::BITS == 64 && block_size == 7 {
        let mut foreign_config = config;
        foreign_config.small_lwe.dimension = LweDimension::new(block_size * (block_count + 1));
        let foreign_context = TfheContext::<T, Table>::try_from_pbs_config(foreign_config).unwrap();
        let foreign_client = ClientKey::generate(foreign_context.parameters(), &mut rng);
        let BlindRotationKey::Block(foreign_key) = KeyGenerator::new(&foreign_context)
            .try_generate_blind_rotation_key(&foreign_client, &mut rng)
            .unwrap()
        else {
            panic!("expected foreign block key");
        };
        let mut foreign = BlockGlweBlindRotationBatchWorkspace::<T, LANES>::new(&foreign_key);
        for invalid in 0..4 {
            let mut inputs = inputs.clone();
            let mut outputs = expected.clone();
            for output in &mut outputs {
                output.as_mut().fill(T::ONE);
            }
            match invalid {
                0 => inputs[16] = primus_lattice::lwe::Lwe::new(vec![T::ONE; 2]),
                1 => outputs[16] = primus_lattice::glwe::Glwe::new(vec![T::ONE; 1]),
                2 => {
                    outputs.pop();
                }
                _ => {}
            }
            let workspace = if invalid == 3 {
                &mut foreign
            } else {
                &mut batch
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                workspace.blind_rotate_lookup_table_many_to(
                    &key,
                    &inputs,
                    &lut,
                    &rotation,
                    &mut outputs,
                    context.table(),
                );
            }));
            assert!(result.is_err(), "invalid boundary case {invalid}");
            assert!(
                outputs
                    .iter()
                    .all(|ct| ct.as_ref().iter().all(|&x| x == T::ONE))
            );
        }
    }
}

/// Raw block BR is checked against integer negacyclic rotation, independently
/// of LUT compilation or message decoding. q=2N makes every input an exact
/// exponent, including 0, N and 2N-1; both words keep canonical output at Q.
#[test]
fn block_raw_rotation_matches_integer_oracle() {
    check_block_raw_rotation::<u32, U32NttTable>(67_104_769);
    check_block_raw_rotation::<u64, U64NttTable>(1_125_899_906_826_241);
}

fn check_block_raw_rotation<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    ring_modulus_value: T,
) {
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_ntt::{
        ClientKey, KeyGenerator, block::BlockGlweBlindRotationWorkspace, key::BlindRotationKey,
    };

    // Include a single empty block and every singleton position, then multiple
    // blocks with an empty first/last block and an entirely zero logical secret.
    let secrets: &[(usize, &[u8])] = &[
        (3, &[0, 0, 0]),
        (3, &[1, 0, 0]),
        (3, &[0, 1, 0]),
        (3, &[0, 0, 1]),
        (3, &[0, 0, 0, 0, 0, 0]),
        (3, &[0, 0, 0, 0, 1, 0]),
        (3, &[0, 0, 1, 0, 0, 0]),
        (3, &[0, 1, 0, 1, 0, 0]),
        // Four-source aggregation and its one-source tail use this wider block.
        (5, &[0, 0, 0, 0, 1, 0, 1, 0, 0, 0]),
    ];
    let n = 32;
    for occupancy in [BlockOccupancy::AtMostOne, BlockOccupancy::ExactlyOne] {
        for (case, &(block_size, secret)) in secrets.iter().enumerate() {
            if occupancy == BlockOccupancy::ExactlyOne
                && secret
                    .chunks_exact(block_size)
                    .any(|block| block.iter().sum::<u8>() != 1)
            {
                continue;
            }
            let mut config =
                two_domain_config(BlindRotationMethod::Block, PbsOrder::BootstrapKeyswitch);
            config.small_lwe.dimension = LweDimension::new(secret.len());
            config.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                block_size,
                occupancy,
            };
            config.small_lwe.cipher_modulus = ModulusConfig::Explicit(T::as_from(2 * n));
            config.ring_modulus = ModulusConfig::Explicit(ring_modulus_value);
            config.bsk_dimension = GlweDimension::new(1);
            config.bsk_poly_length = PolyLength::new(n);
            let context = TfheContext::<T, Table, _>::try_from_pbs_config(config).unwrap();
            let mut rng = StdRng::seed_from_u64(530 + case as u64);
            let generated = ClientKey::generate(context.parameters(), &mut rng);
            let client = ClientKey::new(
                primus_lwe::LweSecretKey::new(
                    secret.iter().map(|&s| T::as_from(s)).collect(),
                    config.small_lwe.secret_key_distr,
                    context.parameters().small_lwe().cipher_modulus(),
                ),
                generated.glwe_secret_key().clone(),
                config.order,
            );
            let transformed =
                NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), context.table());
            if case == 4 || (occupancy == BlockOccupancy::ExactlyOne && case == 7) {
                use rand::Rng;

                // Standalone BR-key generation owns the same support check even
                // without ClientKey binding. Reject before consuming row randomness.
                let invalid = primus_lwe::LweSecretKey::new(
                    if occupancy == BlockOccupancy::ExactlyOne {
                        [0, 0, 0, 0, 1, 0].map(T::as_from).to_vec()
                    } else {
                        [1, 1, 0, 0, 0, 0].map(T::as_from).to_vec()
                    },
                    config.small_lwe.secret_key_distr,
                    context.parameters().small_lwe().cipher_modulus(),
                );
                let parameters = context.parameters().blind_rotation_params();
                let mut encryption =
                    primus_glwe::NttGlweGadgetEncryptWorkspace::new(parameters.size());
                let mut invalid_rng = StdRng::seed_from_u64(540);
                let mut untouched = StdRng::seed_from_u64(540);
                assert_eq!(
                BlindRotationKey::try_generate(
                    &invalid,
                    &transformed,
                    parameters,
                    BlindRotationMethod::Block,
                    context.table(),
                    &mut invalid_rng,
                    &mut encryption,
                )
                .err(),
                Some(
                    primus_tfhe_glwe_ntt::KeyGenerationError::BlockBootstrapping(
                        primus_tfhe_glwe_ntt::BlockBootstrappingKeyError::InvalidSecretCoefficients,
                    )
                )
            );
                assert_eq!(invalid_rng.next_u64(), untouched.next_u64());
            }
            let BlindRotationKey::Block(key) = KeyGenerator::new(&context)
                .try_generate_blind_rotation_key(&client, &mut rng)
                .unwrap()
            else {
                panic!("expected direct block key");
            };
            if occupancy == BlockOccupancy::ExactlyOne && case == 7 {
                use rand::Rng;
                // A flat bit-only replay proves no hidden dummy encryption or
                // RNG consumption occurs between the two logical blocks.
                let mut expected_key_rng = StdRng::seed_from_u64(530 + case as u64);
                let _ = ClientKey::generate(context.parameters(), &mut expected_key_rng);
                let parameters = context.parameters().blind_rotation_params();
                let mut expected = vec![T::ZERO; secret.len() * parameters.ggsw_len()];
                let mut encryption =
                    primus_glwe::NttGlweGadgetEncryptWorkspace::new(parameters.size());
                transformed.encrypt_ggsw_constant_batch_coeff_to(
                    client.small_lwe_secret_key().as_ref(),
                    &mut expected,
                    parameters,
                    context.table(),
                    &mut expected_key_rng,
                    &mut encryption,
                );
                assert_eq!(key.as_slice(), expected);
                assert_eq!(rng.next_u64(), expected_key_rng.next_u64());
            }
            let mut workspace = BlockGlweBlindRotationWorkspace::new(&key);
            let rotation = RotationModulusSwitch::new(
                context.parameters().small_lwe().cipher_modulus(),
                2 * n,
                1,
            );
            let modulus = context.parameters().ring_modulus();
            let scalar = ring_modulus_value / T::as_from(128);
            let lut = Polynomial::new(
                (0..n)
                    .map(|i| T::as_from((i * i + i / 3 + 5) % 8) * scalar)
                    .collect::<Vec<_>>(),
            );
            let mut input: primus_lattice::lwe::Lwe<Vec<T>> =
                primus_lattice::lwe::Lwe::zero(secret.len());
            let mut output = context.allocate_accumulator_ciphertext();
            let mut phase = Polynomial::new(vec![T::ZERO; n]);
            let mut scratch = vec![T::ZERO; n];
            for (pattern, body) in [13, 0, n, 2 * n - 1].into_iter().enumerate() {
                let mut selected_sum = 0;
                for (i, (value, &s)) in input.a_mut().iter_mut().zip(secret).enumerate() {
                    let exponent = if pattern == 0 {
                        0
                    } else {
                        [0, n, 2 * n - 1][(i + pattern) % 3]
                    };
                    *value = T::as_from(exponent);
                    selected_sum += exponent * usize::from(s);
                }
                *input.b_mut() = T::as_from(body);
                workspace.blind_rotate_lookup_table_to(
                    &key,
                    &input,
                    &lut,
                    &rotation,
                    &mut output,
                    context.table(),
                );
                assert!(
                    output
                        .as_ref()
                        .iter()
                        .all(|&value| value < ring_modulus_value)
                );
                transformed.decrypt_phase_coeff_to(
                    &output,
                    &mut phase,
                    modulus,
                    context.table(),
                    &mut scratch,
                );
                let exponent = (selected_sum + 2 * n - body) % (2 * n);
                for (i, &value) in lut.as_ref().iter().enumerate() {
                    let destination = i + exponent;
                    let expected = if (destination / n) % 2 == 0 {
                        value
                    } else {
                        modulus.reduce_neg(value)
                    };
                    // This deterministic full-decomposition fixture has wide spacing
                    // to distinguish a wrong rotation/sign from sampled row noise.
                    assert!(
                        phase_error_magnitude(phase.as_ref()[destination % n], expected, modulus)
                            <= scalar >> 4u32,
                        "secret {secret:?}, pattern {pattern}, coefficient {i}"
                    );
                }
            }
        }
    }
}
