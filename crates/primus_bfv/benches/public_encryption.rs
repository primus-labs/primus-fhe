//! Run: cargo bench -p primus_bfv --bench public_encryption
//! Smoke: cargo bench -p primus_bfv --bench public_encryption -- --test
//!
//! Each iteration encrypts once with prepared key/context/output/scratch.
//! Fixed diagnostic parameters exercise 50-bit limbs, not a security preset.

use primus_bfv::{
    BfvCiphertext, BfvDecryptWorkspace, BfvParameters, BfvPublicKey, BfvPublicKeyEncryptor,
    BfvSecretKeyContext,
};
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::DecompositionBaseLog;
use primus_encoding::PlaintextEmbedding;
use primus_glwe_rns::{
    DcrtGlweCiphertext, DcrtGlwePublicKey, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{ggsw::DcrtGgsw, workspace::DcrtGlevMulWorkspace};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_rns::Residues;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn bench_public_encryption(c: &mut Criterion) {
    const N: usize = 1024;
    const T: u64 = 12_289;
    const DEGREE: usize = 7;
    const SEED: u64 = 0x5353_4c45_0000_0001;
    let moduli = [1_125_899_906_826_241_u64, 1_125_899_906_629_633].map(BarrettModulus::new);
    let table = U64DcrtTable::new(PolyLength::new(N), &moduli).unwrap();
    let parameters = BfvParameters::new(
        PolyLength::new(N),
        BarrettModulus::new(T),
        BarrettModulus::new(2_199_023_190_017),
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let gadget = parameters.gadget_parameters(DecompositionBaseLog::new(20), None);
    let mut setup_rng = StdRng::seed_from_u64(SEED);
    let coefficient_key = GlweSecretKey::generate(
        parameters.size().glwe_size(),
        parameters.encryption_parameters().secret_key_sampler(),
        &mut setup_rng,
    );
    let secret = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
    let public = DcrtGlwePublicKey::new(
        &secret,
        parameters.encryption_parameters(),
        parameters.base_q(),
        &table,
        &mut setup_rng,
    );
    let secret_context = BfvSecretKeyContext::try_new(&secret, &parameters, &table).unwrap();
    let native_public = BfvPublicKey::new(&secret_context, &mut setup_rng);
    let mut ordinary = BfvPublicKeyEncryptor::try_new(&native_public, &parameters, &table).unwrap();
    let mut raw = public
        .try_bind_raw(
            parameters.encryption_parameters(),
            parameters.base_q(),
            &table,
        )
        .unwrap();
    let mut monomial = public
        .try_bind_gadget(&gadget, parameters.encryption_parameters(), &table)
        .unwrap();
    let mut ordinary_rng = StdRng::seed_from_u64(SEED ^ 1);
    let mut raw_rng = StdRng::seed_from_u64(SEED ^ 2);
    let mut monomial_rng = StdRng::seed_from_u64(SEED ^ 3);
    let mut message = Polynomial::<Vec<u64>>::zero(N);
    for (index, coefficient) in message.as_mut().iter_mut().take(8).enumerate() {
        *coefficient = index as u64 + 1;
    }
    let mut plaintext = CrtPolynomial::<Vec<u64>>::zero(parameters.size().rns_poly_len());
    parameters
        .base_q()
        .wrapping_decompose_small_values_to(message.as_ref(), plaintext.as_mut(), T);
    let mut encoded = CrtPolynomial::<Vec<u64>>::zero(parameters.size().rns_poly_len());
    parameters
        .codec()
        .encode_coeffs_to(&message, &mut encoded, PlaintextEmbedding::Unsigned);
    let mut ordinary_output = BfvCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    let mut raw_output = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    let mut ggsw_output = DcrtGgsw::<Vec<u64>>::zero(gadget.rns_ggsw_len());
    let coefficient = Residues([1_u64, 1]);

    // Validate the same public workflows before any Criterion observation.
    let mut decrypt_workspace = BfvDecryptWorkspace::new(&parameters);
    ordinary.encrypt_plaintext_lift_crt_to(&plaintext, &mut ordinary_output, &mut ordinary_rng);
    assert_eq!(
        secret_context.decrypt(&ordinary_output, &mut decrypt_workspace),
        message,
    );
    raw.encrypt_encoded_crt_to(&encoded, &mut raw_output, &mut raw_rng);
    let mut native_result = BfvCiphertext::zero(parameters.size().rns_glwe_len());
    native_result.set_from_raw_glwe(&raw_output, &parameters);
    assert_eq!(
        secret_context.decrypt(&native_result, &mut decrypt_workspace),
        message
    );
    monomial.encrypt_monomial_ggsw_to(&coefficient, DEGREE, &mut ggsw_output, &mut monomial_rng);
    let mut native_message = BfvCiphertext::zero(parameters.size().rns_glwe_len());
    secret_context.encrypt_to(&message, &mut native_message, &mut setup_rng);
    let mut encrypted_message =
        DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.size().rns_glwe_len());
    native_message.write_raw_glwe_to(&mut encrypted_message, &parameters);
    let encrypted_message = encrypted_message.into_coeff_form(&table);
    let mut external_workspace = DcrtGlevMulWorkspace::new(gadget.size(), parameters.base_q());
    ggsw_output.external_product_to(
        &encrypted_message,
        &mut raw_output,
        gadget.basis(),
        &table,
        parameters.base_q(),
        &mut external_workspace,
    );
    let mut expected = message.clone();
    expected.as_mut().rotate_right(DEGREE);
    for coefficient in &mut expected.as_mut()[..DEGREE] {
        *coefficient = (T - *coefficient) % T;
    }
    native_result.set_from_raw_glwe(&raw_output, &parameters);
    assert_eq!(
        secret_context.decrypt(&native_result, &mut decrypt_workspace),
        expected
    );

    let mut group = c.benchmark_group("public_encryption/N1024/u64/rank1");
    group.bench_function("ordinary_to", |b| {
        b.iter(|| {
            ordinary.encrypt_plaintext_lift_crt_to(
                black_box(&plaintext),
                black_box(&mut ordinary_output),
                &mut ordinary_rng,
            );
        });
    });
    group.bench_function("raw_encoded_to", |b| {
        b.iter(|| {
            raw.encrypt_encoded_crt_to(
                black_box(&encoded),
                black_box(&mut raw_output),
                &mut raw_rng,
            );
        });
    });
    group.bench_function("monomial_ggsw_to", |b| {
        b.iter(|| {
            monomial.encrypt_monomial_ggsw_to(
                black_box(&coefficient),
                DEGREE,
                black_box(&mut ggsw_output),
                &mut monomial_rng,
            );
        });
    });
    group.finish();
}

criterion_group!(benches, bench_public_encryption);
criterion_main!(benches);
