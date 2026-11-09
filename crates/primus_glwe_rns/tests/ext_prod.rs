//! Public GGSW encryption and external product across two wide CRT limbs.
mod support;

use primus_decompose::{DecompositionBaseLog, big_integer::BigUintApproxSignedBasis};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweEncryptionParameters, DcrtGlweCiphertext, DcrtGlwePublicKey,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_lattice::{glwe::DcrtGlwe, workspace::DcrtGlevMulWorkspace};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_rns::RNSBase;
use primus_rns::Residues;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Test GLWE external product: c₂ = GGSW(monomial) ⊡ GLWE(plaintext).
///
/// Given an encrypted monomial X^d (as a GGSW) and an encoded phase m(X)
/// (as a GLWE), the external product yields an encryption of m(X) · X^d mod Q,
/// i.e. the plaintext rotated right by d with sign-flip on the first d coefficients.
#[test]
fn test_external_product() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 32;
    let log_n = poly_length.trailing_zeros();

    let moduli_values: [ValueT; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(PolyLength::new(1usize << log_n), &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    // Prepare codec-free sampling, the gadget basis and keys.
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
    let glev_params = CrtGlevParameters::try_from_parts(inner.size(), base_q, basis).unwrap();
    let sk = GlweSecretKey::generate(size.glwe_size(), inner.secret_key_sampler(), &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);
    let pk = DcrtGlwePublicKey::new(&dcrt_sk, &inner, glev_params.base_q(), &table, &mut rng);

    let parameters = support::RawParameters {
        core: Arc::clone(&inner),
        base: glev_params.base_q().clone(),
    };
    let rns_glwe_len = size.rns_glwe_len();
    let base_q = glev_params.base_q();
    let input: Vec<i128> = (0..poly_length).map(|i| (i % 7) as i128 - 3).collect();
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    let mut glev_workspace = DcrtGlevMulWorkspace::new(glev_params.size(), glev_params.base_q());

    let dcrt_sk_context = dcrt_sk
        .try_bind_raw(
            parameters.encryption_parameters(),
            parameters.base_q(),
            &table,
        )
        .unwrap();
    dcrt_sk_context.encrypt_encoded_crt_to(
        &support::encode_probe(&input, &moduli_values),
        &mut c1,
        &mut rng,
    );

    // Requires coefficient-domain input.
    let c1 = c1.into_coeff_form(&table);

    let mut ggsw_encryptor = pk.try_bind_gadget(&glev_params, &inner, &table).unwrap();

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

        let mut expected = input.clone();
        expected.rotate_right(degree);
        for value in &mut expected[..degree] {
            *value = -*value;
        }
        // Each public gadget column has error Epk*v + eb - sum(ea*s).
        // Bound v by N and the ternary secret's L1 by k*N. Decomposition
        // adds one residual per GLWE component and each signed digit <= B/2.
        let n = poly_length as i128;
        let secret_l1 = dimension as i128 * n;
        let e = i128::from(inner.noise_distribution().maximum_magnitude());
        let public_error = e * (n + 1 + secret_l1);
        let basis = glev_params.basis();
        let residual = if basis.drop_bits() == 0 {
            0
        } else {
            1i128 << (basis.drop_bits() - 1)
        };
        let bound = e
            + (dimension as i128 + 1)
                * n
                * glev_params.level_count().get() as i128
                * i128::from(basis.basis_value() / 2)
                * public_error
            + residual * (1 + secret_l1);
        support::assert_probe_phase(&dcrt_sk, &parameters, &table, &c2, &expected, bound);
    }
}
