// cargo bench -p primus_distr --bench gen_sampler
//
// Benchmarks sampler construction time across sigma ranges.
// Each sampler is tested only in its applicable range:
//   - DiscreteZiggurat:  sigma >= 10   (designed for large sigma)
//   - CDTSampler:        sigma <= 20   (efficient for small-to-moderate sigma)
//   - UnixCDTSampler:    sigma <= 20   (Linux + high_precision feature only)
//
// The overlap [10, 20] lets us compare CDT and Ziggurat side by side.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_distr::{CDTSampler, DiscreteZiggurat};

#[cfg(all(target_os = "linux", feature = "high_precision"))]
use primus_distr::UnixCDTSampler;

const MODULUS_MINUS_ONE: u64 = 1125899906826241 - 1;
const TAIL_CUT: f64 = 12.0;

fn bench_different_sampler(c: &mut Criterion) {
    let mut group = c.benchmark_group("GenSampler");

    for sigma in [1.0, 3.0, 10.0, 15.0, 20.0, 25.0] {
        // Ziggurat is only efficient for large sigma
        if sigma >= 10.0 {
            group.bench_function(format!("DiscreteZiggurat/σ={sigma}"), |b| {
                b.iter(|| {
                    black_box(DiscreteZiggurat::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE));
                })
            });
        }

        // CDT is efficient for small-to-moderate sigma
        if sigma <= 20.0 {
            group.bench_function(format!("CDTSampler/σ={sigma}"), |b| {
                b.iter(|| black_box(CDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE)))
            });
        }

        #[cfg(all(target_os = "linux", feature = "high_precision"))]
        if sigma <= 20.0 {
            group.bench_function(format!("UnixCDTSampler/σ={sigma}"), |b| {
                b.iter(|| black_box(UnixCDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE)))
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_different_sampler);

criterion_main!(benches);
