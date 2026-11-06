//! Local provenance is distinct from raw numerical and actual-secret contracts.
use primus_bgv::{
    BgvAutomorphism, BgvCiphertext, BgvCiphertextBindingError, BgvClient, BgvCollectiveError,
    BgvContext, BgvEvaluationKeyError, BgvEvaluator, BgvKeySwitcher, BgvModulusSwitch,
    BgvMultiplication, BgvParameters, BgvPublicKeyError, BgvRelinearizer, PlaintextEmbedding,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 32;
const Q: [u64; 3] = [
    1_125_899_906_248_961,
    1_125_899_906_051_329,
    1_125_899_904_322_049,
];
fn parameters() -> BgvParameters {
    BgvParameters::try_with_error_distribution(
        PolyLength::new(N),
        BarrettModulus::new(193),
        &Q.map(BarrettModulus::new),
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 21 },
    )
    .unwrap()
}
fn foreign(context: &BgvContext) -> BgvContext {
    BgvContext::try_with_table(parameters(), 3, context.shared_table()).unwrap()
}
fn rejects(operation: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(operation)).is_err());
}
#[derive(Default)]
struct RecordingRng(usize);
impl rand::TryRng for RecordingRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0 += 1;
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 += 1;
        Ok(0)
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0 += 1;
        bytes.fill(0);
        Ok(())
    }
}
impl rand::TryCryptoRng for RecordingRng {}

#[test]
fn import_preserves_storage_and_views_keep_exact_owner_and_level() {
    let context = BgvContext::try_with_levels(parameters(), 3).unwrap();
    let other = foreign(&context);
    let values = vec![0; 2 * context.rns_poly_len(1)];
    let pointer = values.as_ptr();
    let mut bound = context
        .try_bind_ciphertext(BgvCiphertext::from_raw(values), 1)
        .unwrap();
    assert_eq!(bound.as_ref().as_ptr(), pointer);
    assert!(context.check_ciphertext(&bound, 1).is_ok());
    assert!(matches!(
        other.check_ciphertext(&bound.as_view(), 1),
        Err(BgvCiphertextBindingError::ContextMismatch)
    ));
    assert!(matches!(
        context.check_ciphertext(&bound.as_mut_view(), 0),
        Err(BgvCiphertextBindingError::BoundLevel { .. })
    ));
    assert!(matches!(
        other.try_bind_ciphertext(bound.clone(), 1),
        Err(BgvCiphertextBindingError::ContextMismatch)
    ));
    assert!(matches!(
        context.try_bind_ciphertext(bound.clone(), 0),
        Err(BgvCiphertextBindingError::BoundLevel { .. })
    ));
    // Provenance does not certify values after the explicit mutable storage API.
    bound.as_mut()[0] = Q[0];
    assert!(context.check_ciphertext(&bound, 1).is_ok());
    assert!(matches!(
        context.try_bind_ciphertext(bound, 1),
        Err(BgvCiphertextBindingError::NonCanonical { index: 0, .. })
    ));
    assert!(matches!(
        context.try_bind_ciphertext(BgvCiphertext::zero_raw(1), 0),
        Err(BgvCiphertextBindingError::Length { .. })
    ));
    assert!(matches!(
        context.try_bind_ciphertext(BgvCiphertext::zero_raw(0), 3),
        Err(BgvCiphertextBindingError::Level { .. })
    ));
    // Identical values under independent owners do not compare as the same object.
    assert_ne!(context.new_ciphertext(0), other.new_ciphertext(0));
}

#[test]
fn ordinary_operations_reject_foreign_context_before_writes_or_randomness() {
    let context = BgvContext::try_with_levels(parameters(), 3).unwrap();
    let other = foreign(&context);
    let mut rng = StdRng::seed_from_u64(0x13_b6);
    let mut client = BgvClient::generate(&context, &mut rng);
    let foreign_client = BgvClient::generate(&other, &mut rng);
    let public_key = client.public_key(&mut rng);
    assert!(matches!(
        other.public_key_encryptor(&public_key),
        Err(BgvPublicKeyError::ContextMismatch)
    ));
    let config = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let relin = client.relinearization_key(0, config, &mut rng).unwrap();
    let auto_key = client.automorphism_key(0, 5, config, &mut rng).unwrap();
    let switch_key = client
        .key_switching_key(&client, 0, config, &mut rng)
        .unwrap();
    assert!(matches!(
        BgvMultiplication::try_new(&other, &relin),
        Err(BgvEvaluationKeyError::ContextMismatch)
    ));
    assert!(matches!(
        BgvAutomorphism::try_new(&other, &auto_key),
        Err(BgvEvaluationKeyError::ContextMismatch)
    ));
    let mut unexpected = RecordingRng::default();
    assert!(matches!(
        client.key_switching_key(&foreign_client, 0, config, &mut unexpected),
        Err(BgvEvaluationKeyError::ContextMismatch)
    ));
    let plain = Polynomial(vec![1; N]);
    let encrypted = client.encrypt(&plain, &mut rng);
    let mut output = context.new_ciphertext(0);
    output.as_mut().fill(123);
    let before = output.clone();
    let foreign_input = other.new_ciphertext(0);
    let mut evaluator = BgvEvaluator::new(&context, 0);
    rejects(|| evaluator.add_to(&encrypted, &foreign_input, &mut output));
    rejects(|| {
        evaluator.mul_plain_to(
            &foreign_input,
            &plain,
            &mut output,
            PlaintextEmbedding::Unsigned,
        )
    });
    let mut tensor = context.new_quadratic_ciphertext(0);
    let tensor_before = tensor.clone();
    rejects(|| evaluator.mul_to(&encrypted, &foreign_input, &mut tensor));
    assert_eq!(tensor, tensor_before);
    let mut foreign_tensor = other.new_quadratic_ciphertext(0);
    foreign_tensor.as_mut().fill(123);
    let foreign_tensor_before = foreign_tensor.clone();
    rejects(|| evaluator.mul_to(&encrypted, &encrypted, &mut foreign_tensor));
    assert_eq!(foreign_tensor, foreign_tensor_before);
    let mut relinearizer = BgvRelinearizer::try_new(&context, &relin).unwrap();
    rejects(|| relinearizer.relinearize_to(&foreign_tensor, &mut output));
    let mut switcher = BgvKeySwitcher::try_new(&context, &switch_key).unwrap();
    rejects(|| switcher.switch_to(&foreign_input, &mut output));
    let mut wrong_level = context.new_ciphertext(1);
    wrong_level.as_mut().fill(123);
    let wrong_level_before = wrong_level.clone();
    rejects(|| evaluator.add_to(&encrypted, &encrypted, &mut wrong_level));
    assert_eq!(wrong_level, wrong_level_before);

    let mut multiplication = BgvMultiplication::try_new(&context, &relin).unwrap();
    rejects(|| multiplication.multiply_to(&encrypted, &foreign_input, &mut output));
    let mut automorphism = BgvAutomorphism::try_new(&context, &auto_key).unwrap();
    rejects(|| automorphism.apply_to(&foreign_input, &mut output));
    assert_eq!(output, before);
    let mut wrong_output = other.new_ciphertext(0);
    wrong_output.as_mut().fill(123);
    let wrong_before = wrong_output.clone();
    rejects(|| client.encrypt_to(&plain, &mut wrong_output, &mut unexpected));
    assert_eq!(wrong_output, wrong_before);
    let mut encryptor = context.public_key_encryptor(&public_key).unwrap();
    rejects(|| encryptor.encrypt_to(&plain, &mut wrong_output, &mut unexpected));
    assert_eq!(wrong_output, wrong_before);
    assert_eq!(unexpected.0, 0, "rejected provenance must not consume RNG");
    let mut recovered = Polynomial(vec![123; N]);
    rejects(|| client.decrypt_to(&foreign_input, &mut recovered));
    assert_eq!(recovered.as_ref(), &[123; N]);
    let mut phase = DcrtPolynomial(vec![123; context.rns_poly_len(0)]);
    assert!(matches!(
        client.partial_phase_to(&foreign_input, 0, &mut phase),
        Err(BgvCollectiveError::Binding)
    ));
    assert!(phase.as_ref().iter().all(|&x| x == 123));
    let mut drop = BgvModulusSwitch::new(&context, 0);
    let mut lower = context.new_ciphertext(1);
    lower.as_mut().fill(123);
    let lower_before = lower.clone();
    rejects(|| drop.switch_to(&foreign_input, &mut lower));
    assert_eq!(lower, lower_before);
    // Normal recovery infers a real prefix, while raw recovery stays explicit.
    drop.switch_to(&encrypted, &mut lower);
    assert_eq!(client.decrypt(&lower).as_ref(), plain.as_ref());
    let raw = BgvCiphertext::from_raw(lower.as_ref());
    rejects(|| {
        let _ = client.decrypt(&raw);
    });
    assert_eq!(client.decrypt_at_level(&raw, 1).as_ref(), plain.as_ref());
}
