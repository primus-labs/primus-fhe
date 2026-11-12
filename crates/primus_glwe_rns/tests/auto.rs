//! CRT/DCRT automorphism checked against a signed coefficient phase oracle.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlweAutoEvaluator, CrtGlweAutoKey, DcrtGlweAutoEvaluator, DcrtGlweAutoKey,
    DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey,
};
use primus_lattice::glwe::CrtGlwe;
use primus_ntt::UintDcrtTable;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn crt_and_dcrt_automorphisms_match_coefficient_phase_oracle() {
    let parameters = support::probe_parameters(3);
    let n = parameters.poly_length().get();
    let base = parameters.base_q();
    let table = UintDcrtTable::new(parameters.poly_length(), base.moduli()).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let secret = GlweSecretKey::generate(
        parameters.glwe_size(),
        parameters.secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);

    let context = key
        .try_bind_raw(
            parameters.encryption_parameters(),
            parameters.base_q(),
            &table,
        )
        .unwrap();
    let gadget = parameters.gadget(DecompositionBaseLog::new(20), None);

    let message: Vec<_> = (0..n).map(|i| (i % 7) as i128 - 3).collect();
    let mut input = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    context.encrypt_encoded_crt_to(
        &support::encode_probe(&message, base.moduli_values()),
        &mut input,
        &mut rng,
    );
    let coefficient_input = input.clone().into_coeff_form(&table);
    let mut crt_output = CrtGlwe::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let mut dcrt_output = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let bound = i128::from(parameters.core.noise_distribution().maximum_magnitude())
        + support::switch_error_bound(&gadget, parameters.encryption_parameters(), 3 * n as i128);
    for degree in [1, n + 1, 3] {
        // Scatter in Z[X]/(X^N+1), independent of cached ciphertext permutations.
        let mut expected = vec![0; n];
        for (i, &value) in message.iter().enumerate() {
            let target = i * degree % (2 * n);
            expected[target % n] = if target < n { value } else { -value };
        }
        let crt_key = CrtGlweAutoKey::new(
            &gadget,
            parameters.encryption_parameters(),
            &table,
            degree,
            &secret,
            &key,
            &mut rng,
        );
        let dcrt_key = DcrtGlweAutoKey::new(
            &gadget,
            parameters.encryption_parameters(),
            &table,
            degree,
            &key,
            &mut rng,
        );
        let mut crt = CrtGlweAutoEvaluator::new(&crt_key, &gadget, &table);
        let mut dcrt = DcrtGlweAutoEvaluator::new(&dcrt_key, &gadget, &table);
        crt.automorphism_to(&coefficient_input.as_view(), &mut crt_output.as_mut_view());
        crt_output.write_ntt_form(&mut dcrt_output, &table);
        support::assert_probe_phase(&key, &parameters, &table, &dcrt_output, &expected, bound);
        dcrt.automorphism_to(&input.as_view(), &mut dcrt_output.as_mut_view());
        support::assert_probe_phase(&key, &parameters, &table, &dcrt_output, &expected, bound);
    }
}
