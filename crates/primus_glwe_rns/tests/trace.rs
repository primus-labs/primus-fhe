//! Raw CRT/DCRT trace checks the integer projection and its modular normalization.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlweTraceEvaluator, CrtGlweTraceKey, DcrtGlweCiphertext, DcrtGlweRevTraceEvaluator,
    DcrtGlweRevTraceKey, DcrtGlweSecretKey, DcrtGlweTraceEvaluator, DcrtGlweTraceKey,
    GlweSecretKey,
};
use primus_lattice::glwe::CrtGlwe;
use primus_ntt::UintDcrtTable;
use primus_reduce::ReduceInv;
use primus_rns::Residues;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn trace_and_reverse_trace_match_raw_phase_projection() {
    let parameters = support::probe_parameters(2);
    let n = parameters.poly_length().get();
    let base = parameters.base_q();
    let moduli = base.moduli();
    let table = UintDcrtTable::new(parameters.poly_length(), moduli).unwrap();
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

    let crt_key = CrtGlweTraceKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &secret,
        &key,
        &mut rng,
    );
    let dcrt_key = DcrtGlweTraceKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &key,
        &mut rng,
    );
    let rev_key = DcrtGlweRevTraceKey::new(
        &gadget,
        parameters.encryption_parameters(),
        &table,
        &key,
        &mut rng,
    );
    let mut crt = CrtGlweTraceEvaluator::new(&crt_key, &gadget, &table);
    let mut dcrt = DcrtGlweTraceEvaluator::new(&dcrt_key, &gadget, &table);
    let mut reverse = DcrtGlweRevTraceEvaluator::new(&rev_key, &gadget, &table);
    let message: Vec<_> = (0..n).map(|i| (i % 9) as i128 + 1).collect();
    let mut input = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    context.encrypt_encoded_crt_to(
        &support::encode_probe(&message, base.moduli_values()),
        &mut input,
        &mut rng,
    );
    let mut crt_output = CrtGlwe::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let mut output = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let e = i128::from(parameters.core.noise_distribution().maximum_magnitude());
    let bound = n as i128
        * (e + support::switch_error_bound(
            &gadget,
            parameters.encryption_parameters(),
            2 * n as i128,
        ));
    let inverses = Residues(
        moduli
            .iter()
            .map(|q| q.reduce_inv(n as u64))
            .collect::<Vec<_>>(),
    );
    let mut normalized = input.clone();
    normalized.mul_scalar_assign(&inverses, n, parameters.rns_poly_len(), moduli);
    let mut expected = vec![0; n];
    for (cipher, factor) in [(&input, n as i128), (&normalized, 1)] {
        let coefficients = cipher.clone().into_coeff_form(&table);
        expected[0] = message[0] * factor;
        crt.trace_to(&coefficients.as_view(), &mut crt_output.as_mut_view());
        crt_output.write_ntt_form(&mut output, &table);
        support::assert_probe_phase(&key, &parameters, &table, &output, &expected, bound);
        dcrt.trace_to(&cipher.as_view(), &mut output.as_mut_view());
        support::assert_probe_phase(&key, &parameters, &table, &output, &expected, bound);
    }
    reverse.trace_to(&input.as_view(), &mut output.as_mut_view());
    expected[0] = message[0];
    support::assert_probe_phase(&key, &parameters, &table, &output, &expected, bound);
}
