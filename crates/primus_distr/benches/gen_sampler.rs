// cargo bench -p primus_distr --bench gen_sampler
//
// Measures constructing and dropping samplers at small and large supports. Sigma 20
// compares the backends near the portable CDT table limit.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_distr::{CDTSampler, DiscreteZiggurat};

#[cfg(feature = "high_precision")]
use primus_distr::PreciseCDTSampler;

const MODULUS_MINUS_ONE: u64 = 1125899906826241 - 1;
const TAIL_CUT: f64 = 12.0;

fn bench_different_sampler(c: &mut Criterion) {
    let mut group = c.benchmark_group("GenSampler");

    for sigma in [1.0, 3.0, 20.0] {
        group.bench_function(format!("CDTSampler/σ={sigma}"), |b| {
            b.iter(|| black_box(CDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap()))
        });

        #[cfg(feature = "high_precision")]
        group.bench_function(format!("PreciseCDTSampler/σ={sigma}"), |b| {
            b.iter(|| {
                black_box(PreciseCDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap())
            })
        });
    }
    for sigma in [20.0, 30.0] {
        group.bench_function(format!("DiscreteZiggurat/σ={sigma}"), |b| {
            b.iter(|| black_box(DiscreteZiggurat::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap()))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_different_sampler);

criterion_main!(benches);
