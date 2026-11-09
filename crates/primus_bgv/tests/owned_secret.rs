//! Consuming ownership transfer preserves the single key allocation and phase.
use primus_bgv::{BgvClient, BgvContext, BgvParameters};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::SecretKeyDistr;
use primus_modulus::BarrettModulus;
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn consuming_client_transfer_reuses_the_actual_key_after_recovery() {
    let context = BgvContext::try_new(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(32),
            BarrettModulus::new(193),
            &[1_125_899_906_248_961, 1_125_899_906_051_329].map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x1800_00b6);
    let mut client = BgvClient::generate(&context, &mut rng);
    let plain = Polynomial::new((0..32).map(|i| (17 * i % 193) as u64).collect::<Vec<_>>());
    let ciphertext = client.encrypt_centered(&plain, &mut rng);
    assert_eq!(client.decrypt(&ciphertext, 0), plain);
    let key = client.into_secret_key();
    let pointer = key.iter_dcrt_poly().next().unwrap().as_ref().as_ptr();
    let mut client = BgvClient::try_from_secret_key(&context, key).unwrap();
    assert_eq!(client.decrypt(&ciphertext, 0), plain);
    let key = client.into_secret_key();
    assert_eq!(
        key.iter_dcrt_poly().next().unwrap().as_ref().as_ptr(),
        pointer
    );
}
