//! Public storage rebinds real work; malformed frames never become scheme owners.
use primus_bgv::evaluation::{
    BgvAutomorphism, BgvKeySwitcher, BgvModulusSwitch, BgvMultiplication,
};
use primus_bgv::keys::BgvEvaluationKeyConfig;
use primus_bgv::{BgvClient, BgvContext, BgvParameters, PublicObjectLimits};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 32;
const P: u64 = 193;
const Q: [u64; 3] = [1125899905351681, 1125899905744897, 1125899906629633];
fn context() -> BgvContext {
    BgvContext::try_with_levels(
        BgvParameters::try_coefficients(
            PolyLength::new(N),
            BarrettModulus::new(P),
            &Q.map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
        3,
    )
    .unwrap()
}
fn config(context: &BgvContext, hybrid: bool) -> BgvEvaluationKeyConfig {
    if hybrid {
        context
            .hybrid_key_parameters(0, 3, &[1152921504606584833])
            .unwrap()
            .into()
    } else {
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        }
        .into()
    }
}
fn square_and_auto(input: &[u64]) -> Vec<u64> {
    let mut square = vec![0_i128; N];
    for (i, &a) in input.iter().enumerate() {
        for (j, &b) in input.iter().enumerate() {
            square[(i + j) % N] += i128::from(a) * i128::from(b) * if i + j < N { 1 } else { -1 };
        }
    }
    let mut output = vec![0; N];
    for (i, &value) in square.iter().enumerate() {
        let k = 5 * i;
        output[k % N] = (value * if (k / N).is_multiple_of(2) { 1 } else { -1 })
            .rem_euclid(i128::from(P)) as u64;
    }
    output
}

#[test]
fn public_objects_rebind_real_encryption_and_all_three_key_roles() {
    let context = context();
    let limits = PublicObjectLimits::default();
    let restored = BgvContext::from_public_bytes(&context.to_public_bytes(), limits).unwrap();
    assert_eq!(context.to_public_bytes(), restored.to_public_bytes());
    for hybrid in [false, true] {
        let mut rng = StdRng::seed_from_u64(0x23d1 + u64::from(hybrid));
        let alice = BgvClient::generate(&context, &mut rng);
        let mut bob = BgvClient::generate(&context, &mut rng);
        let pk = alice.public_key(&mut rng);
        let relin = alice
            .relinearization_key(0, config(&context, hybrid), &mut rng)
            .unwrap();
        let auto = alice
            .automorphism_key(0, 5, config(&context, hybrid), &mut rng)
            .unwrap();
        let switch = bob
            .key_switching_key(&alice, 0, config(&context, hybrid), &mut rng)
            .unwrap();
        let public = restored
            .import_public_key(&context.export_public_key(&pk).unwrap(), limits)
            .unwrap();
        let relin = restored
            .import_relinearization_key(
                &context.export_relinearization_key(&relin).unwrap(),
                limits,
            )
            .unwrap();
        let auto = restored
            .import_automorphism_key(&context.export_automorphism_key(&auto).unwrap(), limits)
            .unwrap();
        let switch = restored
            .import_key_switching_key(&context.export_key_switching_key(&switch).unwrap(), limits)
            .unwrap();
        let mut plain = restored.new_plaintext();
        plain.as_mut()[..3].copy_from_slice(&[1, 2, P - 1]);
        let ciphertext = restored
            .public_key_encryptor(&public)
            .unwrap()
            .encrypt_centered(&plain, &mut rng);
        let received = context
            .import_ciphertext(&restored.export_ciphertext(&ciphertext, 0).unwrap(), limits)
            .unwrap();
        let mut local = alice;
        assert_eq!(local.decrypt(&received).as_ref(), plain.as_ref());
        let mut product = restored.new_ciphertext(0);
        let mut rotated = restored.new_ciphertext(0);
        let mut switched = restored.new_ciphertext(0);
        let mut lower = restored.new_ciphertext(1);
        BgvMultiplication::try_new(&restored, &relin)
            .unwrap()
            .square_to(&ciphertext, &mut product);
        BgvAutomorphism::try_new(&restored, &auto)
            .unwrap()
            .apply_to(&product, &mut rotated);
        BgvKeySwitcher::try_new(&restored, &switch)
            .unwrap()
            .switch_to(&rotated, &mut switched);
        BgvModulusSwitch::new(&restored, 0).switch_to(&switched, &mut lower);
        let result = context
            .import_ciphertext(&restored.export_ciphertext(&lower, 1).unwrap(), limits)
            .unwrap();
        assert_ne!(result.correction_factor(), 1);
        assert_eq!(result.correction_factor(), lower.correction_factor());
        assert_eq!(
            bob.decrypt(&result).as_ref(),
            square_and_auto(plain.as_ref())
        );
        // Numerically identical remote owners do not bypass ordinary local binding.
        assert!(context.export_ciphertext(&ciphertext, 0).is_err());
    }
}

fn store_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
#[test]
fn malformed_storage_limits_context_role_and_sampler_descriptions_are_checked() {
    let context = context();
    let limits = PublicObjectLimits::default();
    let bytes = context.to_public_bytes();
    for end in [0, 7, 8, 31, bytes.len() - 1] {
        assert!(BgvContext::from_public_bytes(&bytes[..end], limits).is_err());
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(BgvContext::from_public_bytes(&changed, limits).is_err());
    let mut changed = bytes.clone();
    store_u64(&mut changed, 32, u64::MAX);
    assert!(BgvContext::from_public_bytes(&changed, limits).is_err());
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(BgvContext::from_public_bytes(&changed, limits).is_err());
    let mut changed = bytes.clone();
    store_u64(&mut changed, 64, Q[1]);
    assert!(BgvContext::from_public_bytes(&changed, limits).is_err());
    assert!(
        BgvContext::from_public_bytes(
            &bytes,
            PublicObjectLimits {
                max_words: 1,
                ..limits
            }
        )
        .is_err()
    );
    assert!(
        BgvContext::from_public_bytes(
            &bytes,
            PublicObjectLimits {
                max_bytes: bytes.len() - 1,
                ..limits
            }
        )
        .is_err()
    );
    let mut rng = StdRng::seed_from_u64(0x23bad);
    let alice = BgvClient::generate(&context, &mut rng);
    let pk = alice.public_key(&mut rng);
    let ct = context.new_ciphertext(0);
    let encoded = context.export_ciphertext(&ct, 0).unwrap();
    let mut invalid = encoded.clone();
    store_u64(&mut invalid, encoded.len() - 8, u64::MAX);
    assert!(context.import_ciphertext(&invalid, limits).is_err());
    let mut invalid = encoded.clone();
    invalid.push(0);
    assert!(context.import_ciphertext(&invalid, limits).is_err());
    let mut invalid = encoded.clone();
    store_u64(&mut invalid, 24, 2);
    assert!(context.import_ciphertext(&invalid, limits).is_err());
    assert!(context.import_public_key(&encoded, limits).is_err());
    assert!(
        context
            .import_ciphertext(&context.export_public_key(&pk).unwrap(), limits)
            .is_err()
    );
    let mut invalid = encoded.clone();
    let descriptor_len = u64::from_le_bytes(invalid[32..40].try_into().unwrap()) as usize;
    store_u64(&mut invalid, 48 + descriptor_len, 0);
    assert!(context.import_ciphertext(&invalid, limits).is_err());
    for hybrid in [false, true] {
        let key = alice
            .relinearization_key(0, config(&context, hybrid), &mut rng)
            .unwrap();
        let encoded = context.export_relinearization_key(&key).unwrap();
        assert!(context.import_automorphism_key(&encoded, limits).is_err());
        let mut invalid = encoded.clone();
        store_u64(&mut invalid, encoded.len() - 8, u64::MAX);
        assert!(
            context
                .import_relinearization_key(&invalid, limits)
                .is_err()
        );
        assert!(
            context
                .import_relinearization_key(
                    &encoded,
                    PublicObjectLimits {
                        max_words: 1,
                        ..limits
                    }
                )
                .is_err()
        );
    }
    // Public sampler descriptions round-trip all supported tag families.
    for law in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::Binary {
            one_probability: 0.25,
        },
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::Ternary {
            negative_one_probability: 0.25,
            one_probability: 0.5,
        },
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 3 },
        SecretKeyDistr::BlockBinary {
            block_size: 4,
            occupancy: primus_distr::BlockOccupancy::ExactlyOne,
        },
        SecretKeyDistr::FixedHammingWeightTernary { hamming_weight: 5 },
        SecretKeyDistr::FixedCompositionTernary {
            negative_one_weight: 2,
            one_weight: 3,
        },
        SecretKeyDistr::Gaussian {
            standard_deviation: 1.0,
        },
    ] {
        let owner = BgvContext::try_new(
            BgvParameters::try_coefficients(
                PolyLength::new(N),
                BarrettModulus::new(P),
                &Q.map(BarrettModulus::new),
                law,
                ErrorDistribution::Gaussian {
                    standard_deviation: 3.2,
                },
            )
            .unwrap(),
        )
        .unwrap();
        let encoded = owner.to_public_bytes();
        let imported = BgvContext::from_public_bytes(&encoded, limits).unwrap();
        assert_eq!(encoded, imported.to_public_bytes());
        // Geometry alone fits this budget; the actual Gaussian table does not.
        assert!(
            BgvContext::from_public_bytes(
                &encoded,
                PublicObjectLimits {
                    max_words: 10_000,
                    ..limits
                }
            )
            .is_err()
        );
        assert!(
            BgvContext::from_public_bytes(
                &encoded,
                PublicObjectLimits {
                    max_gaussian_standard_deviation: 0.5,
                    ..limits
                }
            )
            .is_err()
        );
    }
}
