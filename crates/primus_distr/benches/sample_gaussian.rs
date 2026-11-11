// cargo bench -p primus_distr --bench sample_gaussian
//
// Measures filling a reusable modular output buffer with each prepared backend
// and a seeded StdRng per case.
// Sigma 20 compares the backends near the portable CDT table limit.

use std::hint::black_box;

use criterion::{
    BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use primus_distr::{CDTSampler, DiscreteZiggurat};
use rand::{SeedableRng, distr::Distribution, rngs::StdRng};

#[cfg(feature = "high_precision")]
use primus_distr::PreciseCDTSampler;

const N: usize = 100_000;
const MODULUS_MINUS_ONE: u64 = 1125899906826241 - 1;
const TAIL_CUT: f64 = 12.0;

/// Construction and buffer allocation are outside the timed filling loop.
fn bench_backend(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    sampler: impl Distribution<u64>,
) {
    let mut rng = StdRng::seed_from_u64(306);
    let mut buf = vec![0u64; N];
    group.bench_function(name, |b| {
        b.iter(|| {
            for (dst, value) in buf.iter_mut().zip((&sampler).sample_iter(&mut rng)) {
                *dst = value;
            }
            black_box(&buf);
        })
    });
}

fn bench_sample(c: &mut Criterion) {
    let mut group = c.benchmark_group("gaussian_backend_sample/std_rng");
    group.throughput(Throughput::Elements(N as u64));

    for sigma in [1.0, 3.19, 20.0] {
        bench_backend(
            &mut group,
            &format!("CDTSampler/σ={sigma}"),
            CDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap(),
        );
        #[cfg(feature = "high_precision")]
        bench_backend(
            &mut group,
            &format!("PreciseCDTSampler/σ={sigma}"),
            PreciseCDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap(),
        );
    }
    for sigma in [20.0, 30.0] {
        bench_backend(
            &mut group,
            &format!("DiscreteZiggurat/σ={sigma}"),
            DiscreteZiggurat::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap(),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_sample);

criterion_main!(benches);
