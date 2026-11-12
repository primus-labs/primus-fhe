//! Run with `cargo bench -p primus_glwe_rns --bench raw_phase`.
//! One prepared rank-two GLWE at N=1024 feeds all operators in both domains.
//! Key/table preparation, encryption and buffer allocation are outside timing.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweAutoEvaluator, CrtGlweAutoKey, CrtGlweEncryptionParameters,
    CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffParallelEvaluator,
    CrtGlweTraceEvaluator, CrtGlweTraceKey, DcrtGlweAutoEvaluator, DcrtGlweAutoKey,
    DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffKey, DcrtGlweExpandCoeffParallelEvaluator,
    DcrtGlweRevTraceEvaluator, DcrtGlweRevTraceKey, DcrtGlweSecretKey, DcrtGlweTraceEvaluator,
    DcrtGlweTraceKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{
    GlweDimension, GlweSize, RnsGlweSize,
    glwe::{CrtGlwe, DcrtGlwe},
};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_rns::RNSBase;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

struct RawPhaseFixture {
    sampling: CrtGlweEncryptionParameters<u64>,
    gadget: CrtGlevParameters<u64, BarrettModulus<u64>>,
    table: U64DcrtTable,
    coeff_key: GlweSecretKey<u64>,
    dcrt_key: DcrtGlweSecretKey<u64>,
    coeff_input: CrtGlwe<Vec<u64>>,
    dcrt_input: DcrtGlwe<Vec<u64>>,
}

impl RawPhaseFixture {
    fn new() -> Self {
        let poly_length = PolyLength::new(1024);
        let moduli = [1_125_899_906_826_241, 1_125_899_906_629_633].map(BarrettModulus::new);
        let table = U64DcrtTable::new(poly_length, &moduli).unwrap();
        let size = RnsGlweSize::new(
            GlweSize::new(GlweDimension::new(2), poly_length),
            moduli.len(),
        );
        let base = RNSBase::new(&moduli).unwrap();
        let sampling =
            CrtGlweEncryptionParameters::try_new(size, &base, SecretKeyDistr::SparseTernary, 3.2)
                .unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let coeff_key =
            GlweSecretKey::generate(size.glwe_size(), sampling.secret_key_sampler(), &mut rng);
        let dcrt_key = DcrtGlweSecretKey::from_coeff_secret_key(&coeff_key, &table);

        // Lift centered small integer phases directly into CRT, without BFV scaling.
        let phase_modulus = 12_289;
        let phase = Polynomial::<Vec<u64>>::random(
            poly_length.get(),
            BarrettModulus::new(phase_modulus),
            &mut rng,
        );
        let mut encoded = CrtPolynomial::<Vec<u64>>::zero(size.rns_poly_len());
        base.wrapping_decompose_small_values_to(phase.as_ref(), encoded.as_mut(), phase_modulus);
        let mut dcrt_input = DcrtGlwe::<Vec<u64>>::zero(size.rns_glwe_len());
        let encryptor = dcrt_key.try_bind_raw(&sampling, &base, &table).unwrap();
        encryptor.encrypt_encoded_crt_to(&encoded, &mut dcrt_input, &mut rng);
        let coeff_input = dcrt_input.clone().into_coeff_form(&table);
        let gadget =
            CrtGlevParameters::try_new(size, base, DecompositionBaseLog::new(20), None).unwrap();

        Self {
            sampling,
            gadget,
            table,
            coeff_key,
            dcrt_key,
            coeff_input,
            dcrt_input,
        }
    }
}

fn bench_automorphism(c: &mut Criterion, fixture: &RawPhaseFixture) {
    let size = fixture.sampling.size();
    let n = size.poly_length().get();
    let mut rng = StdRng::seed_from_u64(43);
    let mut crt_output = CrtGlwe::<Vec<u64>>::zero(size.rns_glwe_len());
    let mut dcrt_output = DcrtGlwe::<Vec<u64>>::zero(size.rns_glwe_len());
    let mut group = c.benchmark_group("automorphism/raw_phase");

    // CRT degrees 1 and N+1 use specialized coefficient permutations. Degree 5
    // exercises the general gather. Key switching is timed in every case.
    for degree in [1, n + 1, 5] {
        let crt_key = CrtGlweAutoKey::new(
            &fixture.gadget,
            &fixture.sampling,
            &fixture.table,
            degree,
            &fixture.coeff_key,
            &fixture.dcrt_key,
            &mut rng,
        );
        let dcrt_key = DcrtGlweAutoKey::new(
            &fixture.gadget,
            &fixture.sampling,
            &fixture.table,
            degree,
            &fixture.dcrt_key,
            &mut rng,
        );
        let mut crt = CrtGlweAutoEvaluator::new(&crt_key, &fixture.gadget, &fixture.table);
        let mut dcrt = DcrtGlweAutoEvaluator::new(&dcrt_key, &fixture.gadget, &fixture.table);
        let label = format!("N={n}/degree={degree}");
        group.bench_function(BenchmarkId::new("CRT", &label), |b| {
            b.iter(|| {
                crt.automorphism_to(black_box(&fixture.coeff_input), black_box(&mut crt_output));
            });
        });
        group.bench_function(BenchmarkId::new("DCRT", &label), |b| {
            b.iter(|| {
                dcrt.automorphism_to(black_box(&fixture.dcrt_input), black_box(&mut dcrt_output));
            });
        });
    }
    group.finish();
}

fn bench_trace(c: &mut Criterion, fixture: &RawPhaseFixture) {
    let size = fixture.sampling.size();
    let mut rng = StdRng::seed_from_u64(44);
    let crt_key = CrtGlweTraceKey::new(
        &fixture.gadget,
        &fixture.sampling,
        &fixture.table,
        &fixture.coeff_key,
        &fixture.dcrt_key,
        &mut rng,
    );
    let dcrt_key = DcrtGlweTraceKey::new(
        &fixture.gadget,
        &fixture.sampling,
        &fixture.table,
        &fixture.dcrt_key,
        &mut rng,
    );
    let reverse_key = DcrtGlweRevTraceKey::new(
        &fixture.gadget,
        &fixture.sampling,
        &fixture.table,
        &fixture.dcrt_key,
        &mut rng,
    );
    let mut crt = CrtGlweTraceEvaluator::new(&crt_key, &fixture.gadget, &fixture.table);
    let mut dcrt = DcrtGlweTraceEvaluator::new(&dcrt_key, &fixture.gadget, &fixture.table);
    let mut reverse = DcrtGlweRevTraceEvaluator::new(&reverse_key, &fixture.gadget, &fixture.table);
    let mut crt_output = CrtGlwe::<Vec<u64>>::zero(size.rns_glwe_len());
    let mut dcrt_output = DcrtGlwe::<Vec<u64>>::zero(size.rns_glwe_len());
    let label = format!("N={}", size.poly_length().get());
    let mut group = c.benchmark_group("trace/raw_phase");

    group.bench_function(BenchmarkId::new("CRT", &label), |b| {
        b.iter(|| crt.trace_to(black_box(&fixture.coeff_input), black_box(&mut crt_output)));
    });
    group.bench_function(BenchmarkId::new("DCRT", &label), |b| {
        b.iter(|| dcrt.trace_to(black_box(&fixture.dcrt_input), black_box(&mut dcrt_output)));
    });
    group.bench_function(BenchmarkId::new("RevHomTrace", &label), |b| {
        b.iter(|| reverse.trace_to(black_box(&fixture.dcrt_input), black_box(&mut dcrt_output)));
    });
    group.finish();
}

fn bench_expansion(c: &mut Criterion, fixture: &RawPhaseFixture) {
    let size = fixture.sampling.size();
    let n = size.poly_length().get();
    let mut rng = StdRng::seed_from_u64(45);
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let label = format!("N={n}");
    let mut group = c.benchmark_group("expand_coeff/raw_phase");
    group.sample_size(10);

    // Each domain reuses its N outputs for serial and two-worker evaluation.
    // Drop the CRT outputs before allocating the full DCRT result.
    {
        let key = CrtGlweExpandCoeffKey::new(
            &fixture.gadget,
            &fixture.sampling,
            &fixture.table,
            &fixture.coeff_key,
            &fixture.dcrt_key,
            &mut rng,
        );
        let mut serial = CrtGlweExpandCoeffEvaluator::new(&key, &fixture.gadget, &fixture.table);
        let mut parallel =
            CrtGlweExpandCoeffParallelEvaluator::new(&key, &fixture.gadget, &fixture.table, 2);
        let mut output = vec![CrtGlwe::<Vec<u64>>::zero(size.rns_glwe_len()); n];
        group.bench_function(BenchmarkId::new("CRT/single", &label), |b| {
            b.iter(|| {
                serial.expand_coefficients_to(
                    black_box(&fixture.coeff_input),
                    black_box(&mut output),
                );
            });
        });
        group.bench_function(BenchmarkId::new("CRT/parallel2", &label), |b| {
            b.iter(|| {
                workers.install(|| {
                    parallel.expand_coefficients_to(
                        black_box(&fixture.coeff_input),
                        black_box(&mut output),
                    );
                });
            });
        });
    }
    let key = DcrtGlweExpandCoeffKey::new(
        &fixture.gadget,
        &fixture.sampling,
        &fixture.table,
        &fixture.dcrt_key,
        &mut rng,
    );
    let mut serial = DcrtGlweExpandCoeffEvaluator::new(&key, &fixture.gadget, &fixture.table);
    let mut parallel =
        DcrtGlweExpandCoeffParallelEvaluator::new(&key, &fixture.gadget, &fixture.table, 2);
    let mut output = vec![DcrtGlwe::<Vec<u64>>::zero(size.rns_glwe_len()); n];
    group.bench_function(BenchmarkId::new("DCRT/single", &label), |b| {
        b.iter(|| {
            serial.expand_coefficients_to(black_box(&fixture.dcrt_input), black_box(&mut output));
        });
    });
    group.bench_function(BenchmarkId::new("DCRT/parallel2", &label), |b| {
        b.iter(|| {
            workers.install(|| {
                parallel
                    .expand_coefficients_to(black_box(&fixture.dcrt_input), black_box(&mut output));
            });
        });
    });
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    let fixture = RawPhaseFixture::new();
    bench_automorphism(c, &fixture);
    bench_trace(c, &fixture);
    bench_expansion(c, &fixture);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
