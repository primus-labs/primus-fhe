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
                client.decrypt_at_level_to(&input, requested_level, &mut output);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&x| x == 99));
    }
}

#[test]
fn local_context_level_provenance_is_preserved_and_raw_adoption_is_explicit() {
    use primus_bfv::{
        BfvAutomorphism, BfvCiphertext, BfvCiphertextBindingError as E, BfvEvaluationKeyError,
        BfvEvaluator, BfvKeySwitcher, BfvModulusSwitch, BfvMultiplier, BfvPublicKeyError,
        BfvRelinearizer,
    };
    use primus_decompose::{DecompositionBaseLog, DecompositionConfig};

    let context = BfvContext::try_with_levels(parameters(32, &Q), 2).unwrap();
    let foreign =
        BfvContext::try_with_table(parameters(32, &Q), 2, context.shared_table()).unwrap();
    let mut rng = StdRng::seed_from_u64(0x13_bf00);
    let mut alice = BfvClient::generate(&context, &mut rng);
    let bob = BfvClient::generate(&context, &mut rng);
    let outsider = BfvClient::generate(&foreign, &mut rng);
    let mut message = context.new_plaintext();
    message.as_mut()[0] = 7;
    let encrypted = alice.encrypt(&message, &mut rng);
    assert_eq!(alice.decrypt(&encrypted.as_view()), message);
    assert!(matches!(
        foreign.check_ciphertext(&encrypted.as_view(), 0),
        Err(E::ContextMismatch)
    ));
    assert!(matches!(
        context.check_ciphertext(&encrypted, 1),
        Err(E::BoundLevel { .. })
    ));
    assert!(matches!(
        foreign.try_bind_ciphertext(encrypted.clone(), 0),
        Err(E::ContextMismatch)
    ));
    assert!(matches!(
        context.try_bind_ciphertext(encrypted.clone(), 1),
        Err(E::BoundLevel { .. })
    ));

    let mut output = context.new_ciphertext(0);
    output.as_mut().fill(99);
    let before = output.clone();
    let evaluator = BfvEvaluator::new(&context, 0);
    let foreign_input = foreign.new_ciphertext(0);
    assert!(
        catch_unwind(AssertUnwindSafe(|| evaluator.add_to(
            &encrypted,
            &foreign_input,
            &mut output
        )))
        .is_err()
    );
    assert_eq!(output, before);
    let mut foreign_output = foreign.new_ciphertext(0);
    foreign_output.as_mut().fill(99);
    let mut failed_rng = StdRng::seed_from_u64(0x13_bf01);
    let expected_rng = StdRng::seed_from_u64(0x13_bf01).next_u64();
    assert!(
        catch_unwind(AssertUnwindSafe(|| alice.encrypt_to(
            &message,
            &mut foreign_output.as_mut_view(),
            &mut failed_rng
        )))
        .is_err()
    );
    assert_eq!(failed_rng.next_u64(), expected_rng);
    assert!(foreign_output.as_ref().iter().all(|&word| word == 99));
    assert!(matches!(
        context.check_ciphertext(&foreign_output.as_mut_view(), 0),
        Err(E::ContextMismatch)
    ));
    let mut plaintext = Polynomial(vec![99; 32]);
    assert!(
        catch_unwind(AssertUnwindSafe(
            || alice.decrypt_to(&foreign_input, &mut plaintext)
        ))
        .is_err()
    );
    assert!(plaintext.as_ref().iter().all(|&word| word == 99));

    let public = alice.public_key(&mut rng);
    assert!(matches!(
        foreign.public_key_encryptor(&public),
        Err(BfvPublicKeyError::ContextMismatch)
    ));
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let relin = alice.relinearization_key(0, config, &mut rng).unwrap();
    let auto = alice.automorphism_key(0, 5, config, &mut rng).unwrap();
    let switch = bob.key_switching_key(&alice, 0, config, &mut rng).unwrap();
    assert!(matches!(
        BfvRelinearizer::try_new(&foreign, &relin),
        Err(BfvEvaluationKeyError::ContextMismatch)
    ));
    assert!(matches!(
        BfvAutomorphism::try_new(&foreign, &auto),
        Err(BfvEvaluationKeyError::ContextMismatch)
    ));
    assert!(matches!(
        BfvKeySwitcher::try_new(&foreign, &switch),
        Err(BfvEvaluationKeyError::ContextMismatch)
    ));
    let mut failed_rng = StdRng::seed_from_u64(0x13_bf02);
    let expected_rng = StdRng::seed_from_u64(0x13_bf02).next_u64();
    assert!(matches!(
        alice.key_switching_key(&outsider, 0, config, &mut failed_rng),
        Err(BfvEvaluationKeyError::ContextMismatch)
    ));
    assert_eq!(failed_rng.next_u64(), expected_rng);

    let mut quadratic = foreign.new_quadratic_ciphertext(0);
    quadratic.as_mut().fill(99);
    let mut multiplier = BfvMultiplier::try_with_default_basis(&context, 0).unwrap();
    assert!(
        catch_unwind(AssertUnwindSafe(
            || multiplier.square_to(&encrypted, &mut quadratic.as_mut_view())
        ))
        .is_err()
    );
    assert!(quadratic.as_ref().iter().all(|&word| word == 99));
    let mut lower = context.new_ciphertext(1);
    BfvModulusSwitch::new(&context, 0).switch_to(&encrypted, &mut lower);
    assert_eq!(alice.decrypt(&lower), message);
    assert!(matches!(context.check_ciphertext(&lower, 1), Ok(())));

    let raw = BfvCiphertext::from_raw(encrypted.as_ref().to_vec());
    assert!(catch_unwind(AssertUnwindSafe(|| alice.decrypt(&raw))).is_err());
    assert_eq!(alice.decrypt_at_level(&raw, 0), message);
    let pointer = raw.as_ref().as_ptr();
    let adopted = context.try_bind_ciphertext(raw, 0).unwrap();
    assert_eq!(adopted.as_ref().as_ptr(), pointer);
    assert_eq!(alice.decrypt(&adopted), message);
    let mut damaged = adopted;
    damaged.as_mut()[0] = Q[0];
    assert!(matches!(
        context.try_bind_ciphertext(damaged, 0),
        Err(E::NonCanonical { index: 0, .. })
    ));
    assert!(matches!(
        context.try_bind_ciphertext(BfvCiphertext::zero_raw(1), 0),
        Err(E::Length { .. })
    ));
    assert!(matches!(
        context.try_bind_ciphertext(BfvCiphertext::zero_raw(0), 2),
        Err(E::Level { .. })
    ));
}
