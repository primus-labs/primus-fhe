//! Public GGSW encryption and external product across two wide CRT limbs.
use primus_decompose::{DecompositionBaseLog, big_integer::BigUintApproxSignedBasis};
use primus_glwe_rns::{
    BfvRnsCodec, CrtGlevParameters, CrtGlweEncryptionParameters, CrtGlweParameters,
    DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace, DcrtGlwePublicKey,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_lattice::{glwe::DcrtGlwe, workspace::DcrtGlevMulWorkspace};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_reduce::ReduceNegSlice;
use primus_rns::RNSBase;
use primus_rns::Residues;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Test GLWE external product: c₂ = GGSW(monomial) ⊡ GLWE(plaintext).
///
/// Given an encrypted monomial X^d (as a GGSW) and an encrypted plaintext m(X)
/// (as a GLWE), the external product yields an encryption of m(X) · X^d mod t,
/// i.e. the plaintext rotated right by d with sign-flip on the first d coefficients.
#[test]
fn test_external_product() {
    type ValueT = u64;

    let dimension = 2;
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
        BigUintApproxSignedBasis::new(base_q.moduli_product(), DecompositionBaseLog::new(30), None);
    let glev_params = CrtGlevParameters::try_from_parts(Arc::clone(&inner), base_q, basis).unwrap();
    let sk = GlweSecretKey::generate(size.glwe_size(), inner.secret_key_sampler(), &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);
    let pk = DcrtGlwePublicKey::new(&dcrt_sk, &inner, glev_params.base_q(), &table, &mut rng);

    // Only the ordinary input/output encoding needs t and gamma.
    let codec = BfvRnsCodec::new(mod_t, glev_params.base_q().clone(), mod_gamma);
    let glwe_params = CrtGlweParameters::try_from_parts(inner, codec).unwrap();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let input: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    let mut glev_workspace = DcrtGlevMulWorkspace::new(glev_params.size(), glev_params.base_q());
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input, &mut c1, &mut rng);

    // Requires coefficient-domain input.
    let c1 = c1.into_coeff_form(&table);

    let gadget_domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();
    let ggsw_encryptor = pk.try_bind_gadget(&gadget_domain).unwrap();

    // Identity, one-position shift and sign-wrapping boundary.
    for degree in [0, 1, poly_length - 1] {
        let ggsw = ggsw_encryptor.encrypt_monomial_ggsw(&Residues([1, 1]), degree, &mut rng);

        ggsw.external_product_to(
            &c1,
            &mut c2,
            glev_params.basis(),
            &table,
            base_q,
            &mut glev_workspace,
        );

        let mut input_rt = input.clone();
        input_rt.as_mut_slice().rotate_right(degree);
        mod_t.reduce_neg_slice_assign(&mut input_rt.as_mut_slice()[..degree]);

        let output = dcrt_sk_context.decrypt(&c2, &mut decrypt_workspace);

        assert_eq!(input_rt.as_ref(), output.as_ref());
    }
}
