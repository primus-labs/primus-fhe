//! The scheme injection boundary preserves the existing raw encryption kernel.

use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_glwe_rns::{
    CrtGlweEncryptionParameters, DcrtGlweCiphertext, DcrtGlweDomain, DcrtGlwePublicKey,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::CrtPolynomial;
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[test]
fn injections_match_raw_encoded_inputs_and_validate_before_callbacks() {
    let n = PolyLength::new(32);
    let moduli = [65537u64, 114689].map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    let table = U64DcrtTable::new(n, &moduli).unwrap();
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(2), n), 2);
    let sampling =
        CrtGlweEncryptionParameters::new(size, &base, SecretKeyDistr::SparseTernary, 3.2);
    let coefficient_key = GlweSecretKey::<u64>::generate(
        size.glwe_size(),
        sampling.secret_key_sampler(),
        &mut StdRng::seed_from_u64(1),
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
    let public = DcrtGlwePublicKey::new(
        &key,
        &sampling,
        &base,
        &table,
        &mut StdRng::seed_from_u64(2),
    );
    // The returned contexts borrow the resources, not these temporary domain values.
    let secret_context = key
        .try_bind_raw(&DcrtGlweDomain::try_new(&sampling, &base, &table).unwrap())
        .unwrap();
    let mut public_context = public
        .try_bind_raw(&DcrtGlweDomain::try_new(&sampling, &base, &table).unwrap())
        .unwrap();
    let message = CrtPolynomial::new(
        (0..size.rns_poly_len())
            .map(|i| (i % 17) as u64)
            .collect::<Vec<_>>(),
    );
    let mut injected = DcrtGlweCiphertext::<Vec<u64>>::zero(size.rns_glwe_len());
    let mut raw = injected.clone();
    let mut calls = 0;
    let mut injected_rng = StdRng::seed_from_u64(3);
    let mut raw_rng = StdRng::seed_from_u64(3);
    secret_context.encrypt_with_body_to(&mut injected, &mut injected_rng, |body| {
        calls += 1;
        assert_eq!(body.as_ref().len(), size.rns_poly_len());
        body.add_assign(&message, n.get(), base.moduli());
    });
    secret_context.encrypt_encoded_crt_to(&message, &mut raw, &mut raw_rng);
    assert_eq!(calls, 1);
    assert_eq!(injected.as_ref(), raw.as_ref());
    assert_eq!(injected_rng.next_u64(), raw_rng.next_u64());

    let mut indices = Vec::new();
    injected.as_mut().fill(123);
    let mut injected_rng = StdRng::seed_from_u64(4);
    let mut raw_rng = StdRng::seed_from_u64(4);
    public_context.encrypt_with_components_to(
        &mut injected,
        &mut injected_rng,
        |index, component| {
            indices.push(index);
            assert_eq!(component.as_ref().len(), size.rns_poly_len());
            if index == size.dimension().get() {
                component.add_assign(&message, n.get(), base.moduli());
            }
        },
    );
    public_context.encrypt_encoded_crt_to(&message, &mut raw, &mut raw_rng);
    assert_eq!(indices, [0, 1, 2]);
    assert_eq!(injected.as_ref(), raw.as_ref());
    assert_eq!(injected_rng.next_u64(), raw_rng.next_u64());

    for length in [size.rns_glwe_len() - 1, size.rns_glwe_len() + 1] {
        let mut bad = DcrtGlweCiphertext::<Vec<u64>>::zero(length);
        bad.as_mut().fill(456);
        let mut rng = StdRng::seed_from_u64(5);
        let mut untouched_rng = StdRng::seed_from_u64(5);
        let mut called = false;
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                secret_context.encrypt_with_body_to(&mut bad, &mut rng, |_| called = true);
            }))
            .is_err()
        );
        assert!(!called);
        assert!(bad.as_ref().iter().all(|&x| x == 456));
        assert_eq!(rng.next_u64(), untouched_rng.next_u64());
        let mut rng = StdRng::seed_from_u64(6);
        let mut untouched_rng = StdRng::seed_from_u64(6);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                public_context.encrypt_with_components_to(&mut bad, &mut rng, |_, _| called = true);
            }))
            .is_err()
        );
        assert!(!called);
        assert!(bad.as_ref().iter().all(|&x| x == 456));
        assert_eq!(rng.next_u64(), untouched_rng.next_u64());
    }
}
