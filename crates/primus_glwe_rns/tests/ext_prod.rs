//! Public GGSW encryption and external product across two wide CRT limbs.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey};
use primus_lattice::{glwe::DcrtGlwe, workspace::DcrtGlevMulWorkspace};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_rns::Residues;
use rand::{SeedableRng, rngs::StdRng};

/// Test GLWE external product: c₂ = GGSW(monomial) ⊡ GLWE(plaintext).
///
/// Given an encrypted monomial X^d (as a GGSW) and an encoded phase m(X)
/// (as a GLWE), the external product yields an encryption of m(X) · X^d mod Q,
/// i.e. the plaintext rotated right by d with sign-flip on the first d coefficients.
#[test]
fn external_product_matches_coefficient_phase_on_the_active_prefix() {
    let dimension = 2;
    let parameters = support::probe_parameters(dimension);
    let inner = parameters.encryption_parameters();
    let base_q = parameters.base_q();
    let poly_length = parameters.poly_length().get();
    let table = UintDcrtTable::new(parameters.poly_length(), base_q.moduli()).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let glev_params = parameters.gadget(DecompositionBaseLog::new(20), None);
    let sk = GlweSecretKey::generate(parameters.glwe_size(), inner.secret_key_sampler(), &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);
    let dcrt_sk_context = dcrt_sk.try_bind_raw(inner, base_q, &table).unwrap();
    let pk = dcrt_sk_context.public_key(&mut rng);

    let rns_glwe_len = parameters.rns_glwe_len();
    let input: Vec<i128> = (0..poly_length).map(|i| (i % 7) as i128 - 3).collect();
    let mut c1 = DcrtGlweCiphertext::<Vec<u64>>::zero(rns_glwe_len);
    let mut c2 = DcrtGlwe::<Vec<u64>>::zero(rns_glwe_len);

    let mut glev_workspace = DcrtGlevMulWorkspace::new(glev_params.size(), glev_params.base_q());

    dcrt_sk_context.encrypt_encoded_crt_to(
        &support::encode_probe(&input, base_q.moduli_values()),
        &mut c1,
        &mut rng,
    );

    // Requires coefficient-domain input.
    let c1 = c1.into_coeff_form(&table);

    let mut ggsw_encryptor = pk.try_bind_gadget(&glev_params, inner, &table).unwrap();

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
        if degree == poly_length - 1 {
            let moduli = base_q.moduli();
            let extended = [
                moduli[0],
                moduli[1],
                BarrettModulus::new(1_125_899_906_031_617),
            ];
            let full_table = UintDcrtTable::new(parameters.poly_length(), &extended).unwrap();
            let reference = c2.clone();
            // Only the table contains the inactive limb. All gadget rows must
            // still be read using the two-limb ciphertext/workspace geometry.
            ggsw.external_product_to(
                &c1,
                &mut c2,
                glev_params.basis(),
                &full_table,
                base_q,
                &mut glev_workspace,
            );
            assert_eq!(c2.as_ref(), reference.as_ref());
        }
    }
}
