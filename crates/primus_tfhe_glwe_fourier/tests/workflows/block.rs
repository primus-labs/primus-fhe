//! Block blind-rotation arithmetic against independent phase oracles.

use primus_encoding::phase_error_magnitude;
use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{BlockOccupancy, GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_reduce::ReduceNeg;
use primus_shape::PolyLength;
use primus_tfhe_glwe_fourier::{BlindRotationMethod, ModulusConfig, PbsOrder, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

use super::oracle::native_material_phase;
use super::parameters::two_domain_config;

/// Quantization is exact at q=2N. Compare the actual coefficient output phase
/// with an independent integer negacyclic rotation, without Fourier decryption
/// or LUT compilation. The fixture allowance covers sampled and FFT error only;
/// it is neither a general numerical-error budget nor a DFR certificate.
#[test]
fn block_raw_rotation_matches_integer_oracle() {
    #[cfg(feature = "rustfft")]
    {
        check_block_raw_rotation::<u32, primus_fft::RustFftTable>();
        check_block_raw_rotation::<u64, primus_fft::RustFftTable>();
    }
    #[cfg(feature = "tfhe-fft")]
    {
        check_block_raw_rotation::<u32, primus_fft::TfheFftTable>();
        check_block_raw_rotation::<u64, primus_fft::TfheFftTable>();
    }
}

fn check_block_raw_rotation<T: TorusFftValue, Table: FftTable>() {
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_fourier::{
        ClientKey, KeyGenerator, block::BlockGlweBlindRotationWorkspace, key::BlindRotationKey,
    };

    // Empty blocks, every position in an odd-width block, an all-zero secret,
    // and a wider block exposing two aggregate pairs and one control tail.
    let secrets: &[(usize, &[u8])] = &[
        (1, &[0]),
        (1, &[1]),
        (2, &[1, 0, 0, 0]),
        (3, &[0, 0, 0]),
        (3, &[1, 0, 0]),
        (3, &[0, 1, 0]),
        (3, &[0, 0, 1]),
        (3, &[0, 0, 0, 0, 0, 0]),
        (3, &[0, 0, 0, 0, 1, 0]),
        (3, &[0, 0, 1, 0, 0, 0]),
        (3, &[0, 1, 0, 1, 0, 0]),
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
            let BlindRotationKey::Block(key) = KeyGenerator::new(&context)
                .try_generate_blind_rotation_key(&client, &mut rng)
                .unwrap()
            else {
                panic!("expected direct block key");
            };
            let mut workspace = BlockGlweBlindRotationWorkspace::new(&key);
            let rotation = RotationModulusSwitch::new(
                context.parameters().small_lwe().cipher_modulus(),
                2 * n,
                1,
            );
            let modulus = NativeModulus::new();
            let scalar = T::ONE << (T::BITS - 7);
            let lut = Polynomial::new(
                (0..n)
                    .map(|i| T::as_from((i * i + i / 3 + 5) % 8) * scalar)
                    .collect::<Vec<_>>(),
            );
            let mut input: primus_lattice::lwe::Lwe<Vec<T>> =
                primus_lattice::lwe::Lwe::zero(secret.len());
            let mut output = context.allocate_accumulator_ciphertext();
            let mut fft = context.new_fft_engine();
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
                    &mut fft,
                );
                let phase =
                    native_material_phase(output.as_ref(), client.glwe_secret_key().as_slice(), n);
                let exponent = (selected_sum + 2 * n - body) & (2 * n - 1);
                for (i, &value) in lut.as_ref().iter().enumerate() {
                    let destination = i + exponent;
                    let expected = if destination & n == 0 {
                        value
                    } else {
                        modulus.reduce_neg(value)
                    };
                    assert!(
                        phase_error_magnitude(phase[destination & (n - 1)], expected, modulus)
                            <= scalar >> 4u32,
                        "secret {secret:?}, pattern {pattern}, coefficient {i}"
                    );
                }
            }
        }
    }
}
