// cargo bench -p primus_distr --bench sample_gaussian
//
// Benchmarks sampling throughput for each sampler type.
//   - DiscreteZiggurat:  sigma >= 10   (large sigma)
//   - CDTSampler:        sigma <= 20   (default, binary-search CDT)
//   - PreciseCDTSampler: sigma <= 20 (high_precision feature only)

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_distr::{CDTSampler, DiscreteZiggurat};
use rand::distr::Distribution;

#[cfg(feature = "high_precision")]
use primus_distr::PreciseCDTSampler;

const N: usize = 100_000;
const MODULUS_MINUS_ONE: u64 = 1125899906826241 - 1;
const TAIL_CUT: f64 = 12.0;

fn bench_sample(c: &mut Criterion) {
    let mut group = c.benchmark_group("gaussian_backend_sample");
    group.throughput(Throughput::Elements(N as u64));

    for sigma in [1.0, 3.19, 10.0, 20.0, 30.0] {
        if sigma <= 20.0 {
            let mut rng = rand::rng();
            let sampler = CDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap();
            let sampler = &sampler;
            let mut buf = vec![0u64; N];
            group.bench_function(format!("CDTSampler/σ={sigma}"), |b| {
                b.iter(|| {
                    for (dst, val) in buf.iter_mut().zip(sampler.sample_iter(&mut rng)) {
                        *dst = val;
                    }
                    black_box(&buf);
                })
            });
        }

        #[cfg(feature = "high_precision")]
        if sigma <= 20.0 {
            let mut rng = rand::rng();
            let sampler = PreciseCDTSampler::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap();
            let sampler = &sampler;
            let mut buf = vec![0u64; N];
            group.bench_function(format!("PreciseCDTSampler/σ={sigma}"), |b| {
                b.iter(|| {
                    for (dst, val) in buf.iter_mut().zip(sampler.sample_iter(&mut rng)) {
                        *dst = val;
                    }
                    black_box(&buf);
                })
            });
        }

        // DiscreteZiggurat — large sigma only
        if sigma >= 10.0 {
            let mut rng = rand::rng();
            let sampler = DiscreteZiggurat::new(sigma, TAIL_CUT, MODULUS_MINUS_ONE).unwrap();
            let sampler = &sampler;
            let mut buf = vec![0u64; N];
            group.bench_function(format!("DiscreteZiggurat/σ={sigma}"), |b| {
                b.iter(|| {
                    for (dst, val) in buf.iter_mut().zip(sampler.sample_iter(&mut rng)) {
                        *dst = val;
                    }
                    black_box(&buf);
                })
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_sample);

criterion_main!(benches);
