use primus_decompose::{DecompositionBaseLog, big_integer::BigUintApproxSignedBasis};
use primus_glwe_rns::{
    BfvRnsCodec, CrtGlevParameters, CrtGlweEncryptionParameters, CrtGlweParameters,
    DcrtGadgetDomain, DcrtGlweDecryptWorkspace, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_lattice::{glev::DcrtGlev, glwe::DcrtGlwe, workspace::DcrtGlevMulWorkspace};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::{BigUintPolynomial, CrtPolynomial, DcrtPolynomial, Polynomial};
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

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

    let encryptor = dcrt_sk.try_bind_gadget(&domain).unwrap();

    // Both representations reject incomplete or oversized layouts before they
    // consume coins or touch even a borrowed, dirty destination.
    for is_dcrt in [false, true] {
        for (input_len, output_len) in [
            (0, rns_glev_len),
            (rns_poly_len - 1, rns_glev_len),
            (rns_poly_len + 1, rns_glev_len),
            (rns_poly_len, 0),
            (rns_poly_len, rns_glev_len - 1),
            (rns_poly_len, rns_glev_len + 1),
        ] {
            let input = vec![1; input_len];
            let mut output = vec![2; output_len + 2];
            let mut rejected_rng = StdRng::seed_from_u64(0x474c_4556);
            let mut untouched_rng = StdRng::seed_from_u64(0x474c_4556);
            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut output_view = DcrtGlev::new(&mut output[1..output_len + 1]);
                if is_dcrt {
                    encryptor.encrypt_dcrt_to(
                        &DcrtPolynomial::new(input.as_slice()),
                        &mut output_view,
                        &mut rejected_rng,
                    );
                } else {
                    encryptor.encrypt_crt_to(
                        &CrtPolynomial::new(input.as_slice()),
                        &mut output_view,
                        &mut rejected_rng,
                    );
                }
            }));
            assert!(
                result.is_err(),
                "is_dcrt={is_dcrt}, input_len={input_len}, output_len={output_len}"
            );
            assert!(output.iter().all(|&value| value == 2));
            assert_eq!(
                rand::Rng::next_u64(&mut rejected_rng),
                rand::Rng::next_u64(&mut untouched_rng)
            );
        }
    }

    // NTT linearity makes the CRT and pretransformed DCRT paths identical for
    // the same coins. Repeat with dirty reused allocations and borrowed views;
    // the resulting GLev also feeds the independent multiplication check below.
    let mut msg1_dcrt = DcrtPolynomial::new(msg1.as_ref().to_vec());
    table.transform_slice(msg1_dcrt.as_mut());
    let mut dcrt_storage = vec![0; rns_glev_len + 2];
    for seed in [0x474c_4556, 0x474c_4557] {
        dcrt_glev.as_mut().fill(ValueT::MAX);
        dcrt_storage.fill(ValueT::MAX - 1);
        let mut crt_rng = StdRng::seed_from_u64(seed);
        let mut dcrt_rng = StdRng::seed_from_u64(seed);
        encryptor.encrypt_crt_to(&msg1.as_view(), &mut dcrt_glev.as_mut_view(), &mut crt_rng);
        let mut dcrt_view = DcrtGlev::new(&mut dcrt_storage[1..rns_glev_len + 1]);
        encryptor.encrypt_dcrt_to(&msg1_dcrt.as_view(), &mut dcrt_view, &mut dcrt_rng);
        assert_eq!(dcrt_glev.as_ref(), dcrt_view.as_ref());
        assert_eq!(
            rand::Rng::next_u64(&mut crt_rng),
            rand::Rng::next_u64(&mut dcrt_rng)
        );
        assert_eq!(dcrt_storage[0], ValueT::MAX - 1);
        assert_eq!(dcrt_storage[rns_glev_len + 1], ValueT::MAX - 1);
    }

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
