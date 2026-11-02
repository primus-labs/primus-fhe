//! Raw CRT/DCRT trace checks the integer projection and its modular normalization.
mod support;

use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlweTraceEvaluator, CrtGlweTraceKey, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweRevTraceEvaluator, DcrtGlweRevTraceKey, DcrtGlweSecretKey, DcrtGlweTraceEvaluator,
    DcrtGlweTraceKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, glwe::CrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_reduce::ReduceInv;
use primus_rns::Residues;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn trace_and_reverse_trace_match_raw_phase_projection() {
    let n = PolyLength::new(32);
    let moduli = [1125899906826241u64, 1125899906629633].map(BarrettModulus::new);
    let values = moduli.map(|q| q.value());
    let parameters = support::RawParameters::new(
        GlweDimension::new(2),
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
    let crt_key = CrtGlweTraceKey::new(&domain, &secret, &key, &mut rng);
    let dcrt_key = DcrtGlweTraceKey::new(&domain, &key, &mut rng);
    let rev_key = DcrtGlweRevTraceKey::new(&domain, &key, &mut rng);
    let mut crt = CrtGlweTraceEvaluator::new(&crt_key, &domain);
    let mut dcrt = DcrtGlweTraceEvaluator::new(&dcrt_key, &domain);
    let mut reverse = DcrtGlweRevTraceEvaluator::new(&rev_key, &domain);
    let message: Vec<_> = (0..n.get()).map(|i| (i % 9) as i128 + 1).collect();
    let mut input = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    context.encrypt_encoded_crt_to(
        &support::encode_probe(&message, &values),
        &mut input,
        &mut rng,
    );
    let mut crt_output = CrtGlwe::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let mut output = DcrtGlweCiphertext::<Vec<u64>>::zero(parameters.rns_glwe_len());
    let e = i128::from(parameters.core.noise_distribution().maximum_magnitude());
    let bound = n.get() as i128 * (e + support::switch_error_bound(&gadget, 2 * n.get() as i128));
    let inverses = Residues(values.map(|q| BarrettModulus::new(q).reduce_inv(n.get() as u64)));
    for normalized in [false, true] {
        let mut input = input.clone();
        if normalized {
            input.mul_scalar_assign(&inverses, n.get(), parameters.rns_poly_len(), &moduli);
        }
        let coefficients = input.clone().into_coeff_form(&table);
        let mut expected = vec![0; n.get()];
        expected[0] = message[0] * if normalized { 1 } else { n.get() as i128 };
        crt.trace_to(&coefficients.as_view(), &mut crt_output.as_mut_view());
        crt_output.write_ntt_form(&mut output, &table);
        support::assert_probe_phase(&key, &parameters, &table, &output, &expected, bound);
        dcrt.trace_to(&input.as_view(), &mut output.as_mut_view());
        support::assert_probe_phase(&key, &parameters, &table, &output, &expected, bound);
    }
    reverse.trace_to(&input.as_view(), &mut output.as_mut_view());
    let saved = output.as_ref().to_vec();
    reverse.trace_to(&input, &mut output);
    assert_eq!(saved, output.as_ref());
    let mut expected = vec![0; n.get()];
    expected[0] = message[0];
    support::assert_probe_phase(&key, &parameters, &table, &output, &expected, bound);
}
