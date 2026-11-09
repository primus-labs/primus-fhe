use primus_decompose::DecompositionBaseLog;
use primus_lattice::GlweDimension;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweParameters, CrtGlweTraceEvaluator, CrtGlweTraceKey, DcrtGadgetDomain,
    DcrtGlweCiphertext, DcrtGlweRevTraceEvaluator, DcrtGlweRevTraceKey, DcrtGlweSecretKey,
    DcrtGlweTraceEvaluator, DcrtGlweTraceKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, Polynomial};

fn bench_trace(c: &mut Criterion) {
    type V = u64;

    let dimension = 2;
    let t: V = 12289;
    let mod_t = BarrettModulus::new(t);
    let gamma: V = 2199023190017;
    let mod_gamma = BarrettModulus::new(gamma);
    let moduli_values: [V; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(BarrettModulus::new);

    let mut rng = StdRng::seed_from_u64(42);

    let mut group = c.benchmark_group("trace");

    for log_n in [10u32, 11, 12] {
        let poly_length = PolyLength::new(1usize << log_n);
        let n = poly_length.get();
        let table = U64DcrtTable::new(poly_length, &moduli).unwrap();

        let glwe_params = CrtGlweParameters::new(
            GlweDimension::new(dimension),
            poly_length,
            mod_t,
            mod_gamma,
            &moduli,
            SecretKeyDistr::SparseTernary,
            3.20,
        );

        let crt_poly_len = glwe_params.rns_poly_len();
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

        // Trace keys
        let crt_trace_key = CrtGlweTraceKey::new(&domain, &sk, &dcrt_sk, &mut rng);

        let dcrt_trace_key = DcrtGlweTraceKey::new(&domain, &dcrt_sk, &mut rng);

        let dcrt_rev_trace_key = DcrtGlweRevTraceKey::new(&domain, &dcrt_sk, &mut rng);

        let table_ref = &table;

        // Ciphertexts
        let input: Polynomial<Vec<V>> = Polynomial::random(n, mod_t, &mut rng);
        let mut msg: CrtPolynomial<Vec<V>> = CrtPolynomial::zero(crt_poly_len);
        let mut c_ntt: DcrtGlwe<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);

        base_q.wrapping_decompose_small_values_to(input.as_ref(), msg.as_mut(), t);
        let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, table_ref).unwrap();
        dcrt_sk_context.encrypt_plaintext_crt_to(&msg, &mut c_ntt, &mut rng);

        let c_coeff: CrtGlwe<Vec<V>> = {
            let tmp = DcrtGlweCiphertext::new(c_ntt.as_ref().to_vec());
            tmp.into_coeff_form(table_ref)
        };

        // Buffers
        let mut crt_result: CrtGlwe<Vec<V>> = CrtGlwe::zero(rns_glwe_len);
        let mut dcrt_result: DcrtGlweCiphertext<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        let mut crt_trace_evaluator = CrtGlweTraceEvaluator::new(&crt_trace_key, &domain);
        let mut dcrt_trace_evaluator = DcrtGlweTraceEvaluator::new(&dcrt_trace_key, &domain);
        let mut dcrt_rev_trace_evaluator =
            DcrtGlweRevTraceEvaluator::new(&dcrt_rev_trace_key, &domain);

        let n_label = format!("N={n}");

        group.bench_function(BenchmarkId::new("CRT", &n_label), |b| {
            b.iter(|| {
                crt_trace_evaluator.trace_to(black_box(&c_coeff), black_box(&mut crt_result));
            });
        });

        group.bench_function(BenchmarkId::new("DCRT", &n_label), |b| {
            b.iter(|| {
                dcrt_trace_evaluator.trace_to(black_box(&c_ntt), black_box(&mut dcrt_result));
            });
        });

        group.bench_function(BenchmarkId::new("RevHomTrace", &n_label), |b| {
            b.iter(|| {
                dcrt_rev_trace_evaluator.trace_to(black_box(&c_ntt), black_box(&mut dcrt_result));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_trace);
criterion_main!(benches);
