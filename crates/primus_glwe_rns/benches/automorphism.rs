//! Run: cargo bench -p primus_glwe_rns --bench automorphism
//! Prepared rank-two evaluation on a raw encoded CRT phase, without BFV scaling.
//! Setup, input encryption and buffers are outside timing; this is not an
//! equivalent complete BFV workload or a historical BFV performance comparison.
//! N=1024 is the representative fixture; do not run an implicit size matrix.

use primus_decompose::DecompositionBaseLog;
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweAutoEvaluator, CrtGlweAutoKey, CrtGlweEncryptionParameters,
    DcrtGlweAutoEvaluator, DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey,
    SecretKeyDistr,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_rns::RNSBase;

fn bench_automorphism(c: &mut Criterion) {
    type V = u64;

    let dimension = 2;
    // Small signed diagnostic phase coefficients; this is not a BFV t.
    let phase_modulus: V = 12289;
    let mod_phase = BarrettModulus::new(phase_modulus);
    let moduli_values: [V; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(BarrettModulus::new);

    let mut rng = StdRng::seed_from_u64(42);

    let mut group = c.benchmark_group("automorphism/raw_phase");

    let poly_length = PolyLength::new(1024);
    let n = poly_length.get();
    let table = U64DcrtTable::new(poly_length, &moduli).unwrap();

    let size = RnsGlweSize::new(
        GlweSize::new(GlweDimension::new(dimension), poly_length),
        moduli.len(),
    );
    let base_q = RNSBase::new(&moduli).unwrap();
    let sampling =
        CrtGlweEncryptionParameters::new(size, &base_q, SecretKeyDistr::SparseTernary, 3.20);

    let crt_poly_len = size.rns_poly_len();
    let rns_glwe_len = size.rns_glwe_len();

    let sk = GlweSecretKey::generate(size.glwe_size(), sampling.secret_key_sampler(), &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::new(
        sampling.size(),
        base_q.clone(),
        DecompositionBaseLog::new(20),
        None,
    );

    let table_ref = &table;

    // Raw phase: centered small integer lifts, without a BFV delta.
    let input: Polynomial<Vec<V>> = Polynomial::random(n, mod_phase, &mut rng);
    let mut msg: CrtPolynomial<Vec<V>> = CrtPolynomial::zero(crt_poly_len);
    let mut c_ntt: DcrtGlwe<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    base_q.wrapping_decompose_small_values_to(input.as_ref(), msg.as_mut(), phase_modulus);

    let dcrt_sk_context = dcrt_sk.try_bind_raw(&sampling, &base_q, table_ref).unwrap();
    dcrt_sk_context.encrypt_encoded_crt_to(&msg, &mut c_ntt, &mut rng);

    let c_coeff: CrtGlwe<Vec<V>> = {
        let tmp = DcrtGlweCiphertext::new(c_ntt.as_ref().to_vec());
        tmp.into_coeff_form(table_ref)
    };

    // Buffers
    let mut crt_result: CrtGlwe<Vec<V>> = CrtGlwe::zero(rns_glwe_len);
    let mut dcrt_result: DcrtGlweCiphertext<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    // Identity and N+1 retain their specialized coefficient paths; degree 5
    // exercises the general gather. Key switching remains part of all cases.
    for auto_degree in [1, n + 1, 5] {
        let crt_auto_key = CrtGlweAutoKey::new(
            &glev_params,
            &sampling,
            &table,
            auto_degree,
            &sk,
            &dcrt_sk,
            &mut rng,
        );
        let dcrt_auto_key = DcrtGlweAutoKey::new(
            &glev_params,
            &sampling,
            &table,
            auto_degree,
            &dcrt_sk,
            &mut rng,
        );

        let mut crt_evaluator = CrtGlweAutoEvaluator::new(&crt_auto_key, &glev_params, &table);
        let mut dcrt_evaluator = DcrtGlweAutoEvaluator::new(&dcrt_auto_key, &glev_params, &table);

        let label = format!("N={n}/degree={auto_degree}");

        group.bench_function(BenchmarkId::new("CRT", &label), |b| {
            b.iter(|| {
                crt_evaluator.automorphism_to(black_box(&c_coeff), black_box(&mut crt_result));
            });
        });

        group.bench_function(BenchmarkId::new("DCRT", &label), |b| {
            b.iter(|| {
                dcrt_evaluator.automorphism_to(black_box(&c_ntt), black_box(&mut dcrt_result));
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_automorphism);
criterion_main!(benches);
