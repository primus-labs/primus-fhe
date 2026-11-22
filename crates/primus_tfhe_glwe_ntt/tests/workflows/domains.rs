//! LWE/ring domain binding and coefficient-indexed returns.

use primus_encoding::phase_error_magnitude;
use primus_glwe::{BlockOccupancy, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::PowOf2Modulus;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_reduce::{EncodeSigned, ReduceMul};
use primus_shape::PolyLength;
use primus_tfhe_glwe_ntt::{BlindRotationMethod, ModulusConfig, PbsConfig, PbsOrder, TfheContext};
use rand::{SeedableRng, rngs::StdRng};

use super::parameters::{config, two_domain_config};

/// Imported keys and raw quantizers must agree with the declared input domain.
#[test]
fn input_domain_binding_precedes_output_writes() {
    use primus_tfhe::TfheEvaluationError;
    use primus_tfhe::rotation::RotationModulusSwitch;
    use primus_tfhe_glwe_ntt::key::BlindRotationKey;

    for method in [BlindRotationMethod::Classic, BlindRotationMethod::Block] {
        let config = two_domain_config::<u32>(method, PbsOrder::BootstrapKeyswitch);
        let context = TfheContext::<u32, U32NttTable, _>::try_from_pbs_config(config).unwrap();
        let mut rng = StdRng::seed_from_u64(114);
        let (_, server) = context.try_generate_keys(&mut rng).unwrap();
        // The shape, gadgets and ring modulus agree; only input q differs.
        let mut wrong_config = config;
        wrong_config.small_lwe.cipher_modulus = ModulusConfig::Explicit(512);
        let wrong_context =
            TfheContext::<u32, U32NttTable, _>::try_from_pbs_config(wrong_config).unwrap();
        assert!(matches!(
            wrong_context.evaluator(&server),
            Err(TfheEvaluationError::IncompatibleBlindRotationKey)
        ));

        if method == BlindRotationMethod::Block {
            // Same dimensions/moduli, different joint secret law and row layout.
            let mut other = config;
            other.small_lwe.secret_key_distr = SecretKeyDistr::BlockBinary {
                block_size: 3,
                occupancy: BlockOccupancy::ExactlyOne,
            };
            let other = TfheContext::<u32, U32NttTable, _>::try_from_pbs_config(other).unwrap();
            assert!(matches!(
                other.evaluator(&server),
                Err(TfheEvaluationError::IncompatibleBlindRotationKey)
            ));
        }

        let input = context.allocate_lwe_ciphertext();
        let lut = Polynomial::new(vec![0u32; 128]);
        let mut output = context.allocate_accumulator_ciphertext();
        // Wrong q, wrong 2N, and a nonordinary step must fail before writes.
        for (q, two_n, step) in [(512, 256, 1), (1024, 128, 1), (1024, 256, 4)] {
            let rotation = RotationModulusSwitch::new(PowOf2Modulus::new(q), two_n, step);
            output.as_mut().fill(7);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match server.blind_rotation_key() {
                    BlindRotationKey::Classic(key) => {
                        let mut workspace = primus_tfhe_glwe_ntt::blind_rotation::NttGlweBlindRotationWorkspace::new(key);
                        key.ntt_blind_rotate_lookup_table_to(
                            &input,
                            &lut,
                            &rotation,
                            &mut output,
                            context.parameters().ring_modulus(),
                            context.table(),
                            &mut workspace,
                        );
                    }
                    BlindRotationKey::Block(key) => {
                        let mut workspace =
                            primus_tfhe_glwe_ntt::block::BlockGlweBlindRotationWorkspace::new(key);
                        workspace.blind_rotate_lookup_table_to(
                            key,
                            &input,
                            &lut,
                            &rotation,
                            &mut output,
                            context.table(),
                        );
                    }
                }
            }));
            assert!(result.is_err());
            assert!(output.as_ref().iter().all(|&x| x == 7));
        }
    }
}

/// Build a noiseless ring phase by schoolbook negacyclic convolution, independently
/// of encryption/extraction kernels. Nonconstant masks and two secret polynomials
/// expose signs, coefficient endpoints and a KS target with a partial last polynomial.
fn ring_return_phase<Table: MonomialNttTable<ValueT = u64>, LM>(
    mut config: PbsConfig<u64, LM>,
    small_dimension: usize,
) where
    LM: RingContext<u64> + TryFrom<ModulusConfig<LM>, Error = primus_tfhe::ModulusConfigError>,
{
    use primus_encoding::{PlaintextEmbedding, ScaledCodec};
    use primus_reduce::{Reduce, ReduceAdd, ReduceSub};

    config.small_lwe.dimension = LweDimension::new(small_dimension);
    config.small_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    config.bsk_poly_length = PolyLength::new(64);
    let context = TfheContext::<u64, Table, LM>::try_from_pbs_config(config).unwrap();
    let mut rng = StdRng::seed_from_u64(812);
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    let mut evaluator = context.evaluator(&server).unwrap();
    let ring = context.parameters().ring_modulus();
    let q = context.parameters().small_lwe().cipher_modulus();
    let ring_codec = ScaledCodec::new(16, ring);
    let small_codec = ScaledCodec::new(16, q);
    let decoder = context
        .ring_return_decryptor(client.external_lwe_secret_key(), 16)
        .unwrap();
    let mut input = context.allocate_accumulator_ciphertext();
    let n = config.bsk_poly_length.get();
    let (mask, body) = input.a_b_mut_slices(n);
    for (j, value) in mask.iter_mut().enumerate() {
        *value = ring.reduce(0x9e37_79b9_7f4a_7c15u64.wrapping_mul(j as u64 + 1));
    }
    for (i, value) in body.iter_mut().enumerate() {
        *value = ring_codec.encode_value((i * 7 % 16) as u64, PlaintextEmbedding::Unsigned);
        for (a, secret) in
            primus_poly::PolynomialIter::new(mask, n).zip(client.glwe_secret_key().iter())
        {
            for (j, &s) in secret.iter().enumerate() {
                let term =
                    ring.reduce_mul(a.as_ref()[(i + n - j) & (n - 1)], ring.encode_signed(s));
                *value = if j <= i {
                    ring.reduce_add(*value, term)
                } else {
                    ring.reduce_sub(*value, term)
                };
            }
        }
    }
    let mut output = context.allocate_lwe_ciphertext();
    for index in [0, n / 2 + 3, n - 1] {
        evaluator.return_ring_at_to(input.as_view(), index, output.as_mut_view());
        let message = (index * 7 % 16) as u64;
        let phase = decoder.decrypt_phase(output.as_view()).unwrap();
        if config.order == PbsOrder::KeyswitchBootstrap {
            // Direct extraction is exact: it must not apply a small-secret KS.
            assert_eq!(
                phase,
                ring_codec.encode_value(message, PlaintextEmbedding::Unsigned)
            );
        } else {
            let expected = small_codec.encode_value(message, PlaintextEmbedding::Unsigned);
            let bound = small_codec.encode_value(1, PlaintextEmbedding::Unsigned) / 16;
            assert!(phase_error_magnitude(phase, expected, q) < bound);
        }
        assert_eq!(decoder.decrypt(output.as_view()).unwrap(), message);
    }

    // The public boundary rejects malformed complete ciphertexts, not just a
    // dimension rounded down from their storage length, before touching output.
    let input_len = input.as_ref().len();
    let output_len = output.as_ref().len();
    for (input_len, index, output_len) in [
        (input_len, n, output_len),
        (input_len, usize::MAX, output_len),
        (input_len - 1, 0, output_len),
        (input_len + 1, 0, output_len),
        (input_len, 0, output_len - 1),
        (input_len, 0, output_len + 1),
        (input_len, 0, 0),
    ] {
        let input = primus_glwe::GlweCiphertext::new(vec![0u64; input_len]);
        let mut output = primus_lwe::LweCiphertext::new(vec![7u64; output_len]);
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.return_ring_at_to(input.as_view(), index, output.as_mut_view());
        }));
        assert!(failed.is_err());
        assert!(output.as_ref().iter().all(|&x| x == 7));
    }
}

#[test]
fn ring_return_phase_and_layout_boundaries() {
    for dimension in [3, 69] {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            let mut same = config(BlindRotationMethod::Classic);
            same.order = order;
            let mut split = two_domain_config(BlindRotationMethod::Classic, order);
            split.small_lwe.cipher_modulus = ModulusConfig::Explicit(1u64 << 24);
            ring_return_phase::<U64NttTable, _>(same, dimension);
            ring_return_phase::<U64NttTable, _>(split, dimension);
        }
    }
}
