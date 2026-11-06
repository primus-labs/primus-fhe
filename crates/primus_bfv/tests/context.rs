use primus_bfv::{BfvClient, BfvContext, BfvContextError, BfvParameters};
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

const Q: [u64; 2] = [1_125_899_906_826_241, 1_125_899_906_629_633];

fn parameters(n: usize, q: &[u64]) -> BfvParameters {
    BfvParameters::try_new(
        PolyLength::new(n),
        BarrettModulus::new(257),
        BarrettModulus::new(2_199_023_190_017),
        &q.iter()
            .copied()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>(),
        SecretKeyDistr::UniformBinary,
        1.0,
    )
    .unwrap()
}

#[test]
fn context_and_import_reject_incompatible_resources() {
    for requested in [0, 3, usize::MAX] {
        assert!(matches!(
            BfvContext::try_with_levels(parameters(32, &Q), requested),
            Err(BfvContextError::LevelCount { .. })
        ));
    }
    // The highest product has ample scale, but its last remaining prime would
    // fail the codec's conservative unsigned-encoding recovery condition.
    let small = parameters(32, &[12_289, 114_689]);
    assert!(matches!(
        BfvContext::try_with_levels(small, 2),
        Err(BfvContextError::Encoding(_))
    ));
    assert!(matches!(
        BfvContext::try_new(parameters(32, &[65_539])),
        Err(BfvContextError::Transform(_))
    ));

    let context = BfvContext::try_with_levels(parameters(32, &Q), 2).unwrap();
    let shared = BfvContext::try_with_table(parameters(32, &Q), 2, context.shared_table()).unwrap();
    assert!(std::ptr::eq(context.table(), shared.table()));
    assert_eq!(shared.codec(1).moduli_values(), &Q[..1]);
    let mut rng = StdRng::seed_from_u64(0x6060);
    for (n, q) in [(64, Q.to_vec()), (32, vec![Q[1], Q[0]]), (32, vec![Q[0]])] {
        let foreign = parameters(n, &q);
        let table = U64DcrtTable::new(foreign.poly_length(), foreign.base_q().moduli()).unwrap();
        let key = GlweSecretKey::generate(
            foreign.size().glwe_size(),
            foreign.encryption_parameters().secret_key_sampler(),
            &mut rng,
        );
        let key = DcrtGlweSecretKey::from_coeff_secret_key(&key, &table);
        assert!(BfvClient::try_from_secret_key(&context, key).is_err());
        assert!(matches!(
            BfvContext::try_with_table(parameters(32, &Q), 2, Arc::new(table)),
            Err(BfvContextError::Binding(_))
        ));
    }
}

#[test]
fn client_rejects_invalid_plaintext_before_randomness_and_invalid_recovery_before_writes() {
    let context = BfvContext::try_with_levels(parameters(32, &Q), 2).unwrap();
    let mut client = BfvClient::generate(&context, &mut StdRng::seed_from_u64(0x6061));
    for input in [vec![0; 31], vec![0; 33], vec![257; 32]] {
        for centered in [false, true] {
            let mut rng = StdRng::seed_from_u64(0x6062);
            let mut expected_rng = StdRng::seed_from_u64(0x6062);
            let mut output = context.new_ciphertext(0);
            output.as_mut().fill(99);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    if centered {
                        client.encrypt_centered_to(&Polynomial(&input[..]), &mut output, &mut rng);
                    } else {
                        client.encrypt_to(&Polynomial(&input[..]), &mut output, &mut rng);
                    }
                }))
                .is_err()
            );
            assert!(output.as_ref().iter().all(|&x| x == 99));
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }
    for (input_level, requested_level, output_length) in
        [(0, 1, 32), (1, 0, 32), (0, 2, 32), (0, 0, 31)]
    {
        let input = context.new_ciphertext(input_level);
        let mut output = Polynomial(vec![99; output_length]);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                client.decrypt_to(&input, requested_level, &mut output);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 99));
    }
}
