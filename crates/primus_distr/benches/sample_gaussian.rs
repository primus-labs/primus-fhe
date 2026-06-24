// cargo bench -p primus_distr --bench sample_gaussian
//
// Benchmarks sampling throughput for each sampler type.
// Sigma ranges match gen_sampler.rs:
//   - DiscreteZiggurat:  sigma >= 10
//   - CDTSampler:        sigma <= 20
//   - UnixCDTSampler:    sigma <= 20  (Linux + high_precision feature only)

use criterion::{Criterion, criterion_group, criterion_main};
use primus_distr::{CDTSampler, DiscreteZiggurat};
use rand::distr::Distribution;

#[cfg(all(target_os = "linux", feature = "high_precision"))]
use primus_distr::UnixCDTSampler;

const N: usize = 100_000;
const MODULUS_MINUS_ONE: u64 = 1125899906826241 - 1;
const TAIL_CUT: f64 = 12.0;

fn bench_sample(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sample");

    for sigma in [3.19, 10.0, 16.0, 20.0, 25.0] {
        // Ziggurat is only efficient for large sigma
        if sigma >= 10.0 {
            let mut rng = rand::rng();
            let ziggurat = DiscreteZiggurat::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE);
            group.bench_function(format!("DiscreteZiggurat/σ={sigma}"), |b| {
                b.iter(|| {
                    for _ in 0..N {
                        ziggurat.sample(&mut rng);
                    }
                })
            });
        }

        // CDT is efficient for small-to-moderate sigma
        if sigma <= 20.0 {
            let mut rng = rand::rng();
            let cdt = CDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE);
            group.bench_function(format!("CDTSampler/σ={sigma}"), |b| {
                b.iter(|| {
                    for _ in 0..N {
                        cdt.sample(&mut rng);
                    }
                })
            });
        }

        #[cfg(all(target_os = "linux", feature = "high_precision"))]
        if sigma <= 20.0 {
            let mut rng = rand::rng();
            let unix_cdt = UnixCDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE);
            group.bench_function(format!("UnixCDTSampler/σ={sigma}"), |b| {
                b.iter(|| {
                    for _ in 0..N {
                        unix_cdt.sample(&mut rng);
                    }
                })
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_sample);

criterion_main!(benches);
