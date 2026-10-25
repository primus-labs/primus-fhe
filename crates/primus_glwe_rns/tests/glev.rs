use primus_decompose::{DecompositionBaseLog, big_integer::BigUintApproxSignedBasis};
use primus_glwe_rns::{
    BfvRnsCodec, CrtGlevParameters, CrtGlweEncryptionParameters, CrtGlweParameters,
    DcrtGadgetDomain, DcrtGlweDecryptWorkspace, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_lattice::{glev::DcrtGlev, glwe::DcrtGlwe, workspace::DcrtGlevMulWorkspace};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::{BigUintPolynomial, CrtPolynomial, Polynomial};
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Test GLev–BigUint multiplication correctness.
///
/// Given two plaintexts m₁(X), m₂(X), the test verifies that:
///   GLev(m₁) ⊡ CRT(δ·m₂)  decrypts to  m₁ · m₂ mod t
///
/// m₁ is encrypted as a GLev gadget (key-switching key format).
/// m₂ is CRT-encoded with delta scaling and composed into a BigUint polynomial.
/// The GLev–BigUint product is a single GLWE ciphertext encrypting the product.
#[test]
fn test_rns_glev() {
    type ValueT = u64;

    let dimension = 3;
    let poly_length: usize = 32;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(PolyLength::new(1usize << log_n), &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    // Prepare sampling, the gadget basis and keys before choosing BFV encoding.
    let base_q = RNSBase::new(&moduli).unwrap();
    let size = RnsGlweSize::new(
        GlweSize::new(GlweDimension::new(dimension), table.poly_length()),
        base_q.moduli_count(),
    );
    let inner = Arc::new(CrtGlweEncryptionParameters::new(
        size,
        &base_q,
        SecretKeyDistr::SparseTernary,
        3.20,
    ));
    let basis =
        BigUintApproxSignedBasis::new(base_q.moduli_product(), DecompositionBaseLog::new(20), None);
    let glev_params = CrtGlevParameters::try_from_parts(Arc::clone(&inner), base_q, basis).unwrap();
    let sk = GlweSecretKey::generate(size.glwe_size(), inner.secret_key_sampler(), &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    // Only the ordinary input/output encoding needs t and gamma.
    let codec = BfvRnsCodec::new(mod_t, glev_params.base_q().clone(), mod_gamma);
    let glwe_params = CrtGlweParameters::try_from_parts(inner, codec).unwrap();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();
    let rns_poly_len = glwe_params.rns_poly_len();
    let big_uint_poly_len = glwe_params.big_uint_poly_len();

    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();
    let rns_glev_len = glev_params.rns_glev_len();

    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());
    let mut glev_workspace = DcrtGlevMulWorkspace::new(glev_params.size(), glev_params.base_q());

    let mut dcrt_glev: DcrtGlev<Vec<ValueT>> = DcrtGlev::zero(rns_glev_len);

    let mut desired: Polynomial<Vec<ValueT>> = Polynomial::zero(poly_length);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let input2: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);

    input1.naive_mul_to(&input2, &mut desired, mod_t);

    // input1 is decomposed into CRT form and encrypted as a GLev structure.
    let mut msg1: CrtPolynomial<Vec<ValueT>> = CrtPolynomial::zero(rns_poly_len);
    base_q.wrapping_decompose_small_values_to(input1.as_ref(), msg1.as_mut(), t);

    dcrt_sk.try_bind_gadget(&domain).unwrap().encrypt_crt_to(
        &msg1.as_view(),
        &mut dcrt_glev.as_mut_view(),
        &mut rng,
    );

    // m₂ is decomposed into CRT, then scaled by δ (so it represents
    // δ·m₂ mod Q in the RNS basis), then composed into BigUint form.
    let mut msg2_big_uint_poly: BigUintPolynomial<Vec<ValueT>> =
        BigUintPolynomial::zero(big_uint_poly_len);

    let mut msg2: CrtPolynomial<Vec<ValueT>> = CrtPolynomial::zero(rns_poly_len);

    base_q.wrapping_decompose_small_values_to(input2.as_ref(), msg2.as_mut(), t);

    msg2.mul_factor_assign(
        glwe_params.delta_factor_mod_q().as_ref(),
        poly_length,
        glwe_params.cipher_moduli_value(),
    );

    let mut compose_scratch = vec![0; base_q.moduli_count()];
    base_q.compose_big_uint_values_to(
        msg2.as_ref(),
        msg2_big_uint_poly.as_mut_slice(),
        poly_length,
        &mut compose_scratch,
    );

    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlwe::zero(rns_glwe_len);

    dcrt_glev.mul_big_uint_polynomial_to(
        &msg2_big_uint_poly,
        &mut c1,
        glev_params.basis(),
        &table,
        base_q,
        &mut glev_workspace,
    );

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    let m_dec = dcrt_sk_context.decrypt(&c1, &mut decrypt_workspace);

    assert_eq!(m_dec, desired);

    // Reuse the dirty workspace. A zero product must overwrite scratch data
    // without changing the accumulator or requiring a separate workspace reset.
    let previous = c1.clone();
    msg2_big_uint_poly.as_mut_slice().fill(0);
    c1.add_dcrt_glev_mul_big_uint_polynomial_assign(
        &dcrt_glev,
        &msg2_big_uint_poly,
        glev_params.basis(),
        &table,
        base_q,
        &mut glev_workspace,
    );
    assert_eq!(c1.as_ref(), previous.as_ref());
}
