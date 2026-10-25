//! CRT/DCRT trace and reverse trace, including modular-inverse normalization.
use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweParameters, CrtGlweTraceEvaluator, CrtGlweTraceKey, DcrtGadgetDomain,
    DcrtGlweCiphertext, DcrtGlweDecryptWorkspace, DcrtGlweRevTraceEvaluator, DcrtGlweRevTraceKey,
    DcrtGlweSecretKey, DcrtGlweTraceEvaluator, DcrtGlweTraceKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::glwe::CrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_reduce::prelude::*;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

/// Test GLWE trace in the coefficient (CRT) domain.
///
/// Trace decrypts the constant coefficient m₀ of a ciphertext:
///   Trace(c) → Enc(N · m₀),  where N = n.
///
/// Multiplying the input ciphertext by N⁻¹ before the trace recovers
/// the original m₀ directly (without the N factor).
/// Both variants are verified.
#[test]
fn test_crt_glwe_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length = PolyLength::new(32);
    let n = poly_length.get();

    let t: ValueT = 12_288; // Even, divisible by N, and not a power of two.
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let trace_key = CrtGlweTraceKey::new(&domain, &sk, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(n, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::zero(rns_glwe_len);
    let mut evaluator = CrtGlweTraceEvaluator::new(&trace_key, &domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

    let mut c1 = c1.into_coeff_form(&table);

    evaluator.trace_to(&c1.as_view(), &mut c2.as_mut_view());

    let c2 = c2.into_ntt_form(&table);

    let trace_msg = dcrt_sk_context.decrypt(&c2, &mut decrypt_workspace);

    // trace_msg[0] = N · input1[0]  (mod t)
    assert_eq!(mod_t.reduce_mul(input1[0], n as ValueT), trace_msg[0]);
    // Other coefficients are zero.
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    let scalar_residue = base_q
        .wrapping_decompose(n as ValueT, t)
        .iter()
        .zip(moduli.iter())
        .map(|(&n, m)| m.reduce_inv(n))
        .collect::<Vec<_>>();

    c1.mul_scalar_assign(
        &primus_rns::Residues(scalar_residue.as_slice()),
        n,
        rns_poly_len,
        &moduli,
    );

    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::new(c2.0);

    evaluator.trace_to(&c1.as_view(), &mut c2.as_mut_view());

    let c2 = c2.into_ntt_form(&table);

    let trace_msg = dcrt_sk_context.decrypt(&c2, &mut decrypt_workspace);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}

/// Test GLWE trace in the NTT (DCRT) domain.
///
/// Same as [`test_crt_glwe_trace`] but the ciphertext stays in NTT domain.
#[test]
fn test_dcrt_glwe_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length = PolyLength::new(32);
    let n = poly_length.get();

    let t: ValueT = 12_288; // Even, divisible by N, and not a power of two.
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let trace_key = DcrtGlweTraceKey::new(&domain, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(n, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut evaluator = DcrtGlweTraceEvaluator::new(&trace_key, &domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

    evaluator.trace_to(&c1.as_view(), &mut c2.as_mut_view());

    let trace_msg = dcrt_sk_context.decrypt(&c2, &mut decrypt_workspace);

    assert_eq!(mod_t.reduce_mul(input1[0], n as ValueT), trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    let scalar_residue = base_q
        .wrapping_decompose(n as ValueT, t)
        .iter()
        .zip(moduli.iter())
        .map(|(&n, m)| m.reduce_inv(n))
        .collect::<Vec<_>>();

    c1.mul_scalar_assign(
        &primus_rns::Residues(scalar_residue.as_slice()),
        n,
        rns_poly_len,
        &moduli,
    );

    evaluator.trace_to(&c1, &mut c2);

    let trace_msg = dcrt_sk_context.decrypt(&c2, &mut decrypt_workspace);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}

/// Test reverse-homomorphic trace in the NTT (DCRT) domain.
///
/// RevHomTrace directly produces an encryption of m₀ (without the N factor),
/// unlike the standard trace which produces N · m₀.
#[test]
fn test_dcrt_glwe_rev_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length = PolyLength::new(32);
    let n = poly_length.get();

    let t: ValueT = 12_288; // Even, divisible by N, and not a power of two.
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(poly_length, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let rev_trace_key = DcrtGlweRevTraceKey::new(&domain, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(n, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut evaluator = DcrtGlweRevTraceEvaluator::new(&rev_trace_key, &domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

    evaluator.trace_to(&c1.as_view(), &mut c2.as_mut_view());

    let first = c2.as_ref().to_vec();
    evaluator.trace_to(&c1, &mut c2);
    assert_eq!(c2.as_ref(), first);

    let trace_msg = dcrt_sk_context.decrypt(&c2, &mut decrypt_workspace);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}
