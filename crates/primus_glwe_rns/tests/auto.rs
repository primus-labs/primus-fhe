//! CRT/DCRT automorphism checked against a signed coefficient phase oracle.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlweAutoEvaluator, CrtGlweAutoKey, DcrtGadgetDomain, DcrtGlweAutoEvaluator, DcrtGlweAutoKey,
    DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, glwe::CrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn crt_and_dcrt_automorphisms_match_coefficient_phase_oracle() {
    let n = PolyLength::new(32);
    let moduli = [1125899906826241u64, 1125899906629633].map(BarrettModulus::new);
    let values = moduli.map(|q| q.value());
    let parameters = support::RawParameters::new(
        GlweDimension::new(3),
        n,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let table = UintDcrtTable::new(n, &moduli).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let secret = GlweSecretKey::generate(
        parameters.glwe_size(),
        parameters.secret_key_sampler(),
        &mut rng,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let raw_domain = parameters.domain(&table);
    let context = key.try_bind_raw(&raw_domain).unwrap();
    let gadget = parameters.gadget(DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let message: Vec<_> = (0..n.get()).map(|i| (i % 7) as i128 - 3).collect();
    let mut input = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    context.encrypt_encoded_crt_to(
        &support::encode_probe(&message, &values),
        &mut input,
        &mut rng,
    );
    let coefficient_input = input.clone().into_coeff_form(&table);
    let mut crt_output = CrtGlwe::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let mut dcrt_output = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let bound = i128::from(parameters.core.noise_distribution().maximum_magnitude())
        + support::switch_error_bound(&gadget, 3 * n.get() as i128);
    for degree in [1, n.get() + 1, 3] {
        // Scatter in Z[X]/(X^N+1), independent of cached ciphertext permutations.
        let mut expected = vec![0; n.get()];
        for (i, &value) in message.iter().enumerate() {
            let target = i * degree % (2 * n.get());
            expected[target % n.get()] = if target < n.get() { value } else { -value };
        }
        let crt_key = CrtGlweAutoKey::new(&domain, degree, &secret, &key, &mut rng);
        let dcrt_key = DcrtGlweAutoKey::new(&domain, degree, &key, &mut rng);
        let mut crt = CrtGlweAutoEvaluator::new(&crt_key, &domain);
        let mut dcrt = DcrtGlweAutoEvaluator::new(&dcrt_key, &domain);
        crt.automorphism_to(&coefficient_input.as_view(), &mut crt_output.as_mut_view());
        let saved = crt_output.as_ref().to_vec();
        crt.automorphism_to(&coefficient_input, &mut crt_output);
        assert_eq!(crt_output.as_ref(), saved);
        crt_output.write_ntt_form(&mut dcrt_output, &table);
        support::assert_probe_phase(&key, &parameters, &table, &dcrt_output, &expected, bound);
        dcrt.automorphism_to(&input.as_view(), &mut dcrt_output.as_mut_view());
        let saved = dcrt_output.as_ref().to_vec();
        dcrt.automorphism_to(&input, &mut dcrt_output);
        assert_eq!(dcrt_output.as_ref(), saved);
        support::assert_probe_phase(&key, &parameters, &table, &dcrt_output, &expected, bound);
    }
}
