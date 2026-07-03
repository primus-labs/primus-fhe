//! Dedicated benchmark for U32NttTable AVX2 vs scalar implementations.
//!
//! Run with:
//! ```sh
//! cargo bench -p primus_ntt --bench avx2_ntt
//! ```
//!
//! On a non-AVX2 machine this will exercise the scalar fallback inside U32NttTable
//! (still worth running for baseline reference).

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable, UintNttTable};
use rand::distr::{Distribution, Uniform};

/// u32 primes < 2^30 covering different bit widths.
const PRIMES: &[u32] = &[
    132120577, // 27-bit
    536813569, // 29-bit
];

/// N values spanning small, medium and large workloads.
const NS: &[usize] = &[256, 1024, 4096, 8192];

/// Pool of pre-generated inputs to avoid re-sampling overhead.
const POOL_SIZE: usize = 16;

fn gen_pool(distr: &Uniform<u32>, n: usize) -> Vec<Vec<u32>> {
    let mut rng = rand::rng();
    (0..POOL_SIZE)
        .map(|_| distr.sample_iter(&mut rng).take(n).collect())
        .collect()
}

fn bench_all(c: &mut Criterion) {
    for &q in PRIMES {
        for &n in NS {
            if !(q - 1).is_multiple_of(2 * n as u32) {
                continue;
            }

            let modulus = BarrettModulus::new(q);
            let log_n = n.trailing_zeros();
            let distr = Uniform::new(0, q).unwrap();

            let avx2_table = U32NttTable::new(log_n, modulus).unwrap();
            let uint32_table = UintNttTable::<u32>::new(log_n, modulus).unwrap();

            let pool = gen_pool(&distr, n);
            let mut idx = 0usize;

            // ---- Forward: lazy ----
            c.bench_function(&format!("AVX2 FWD-lazy q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| avx2_table.lazy_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint32 FWD-lazy q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| uint32_table.lazy_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });

            // ---- Forward: canonical ----
            c.bench_function(&format!("AVX2 FWD-cano q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| avx2_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint32 FWD-cano q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| uint32_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });

            // ---- Inverse: lazy ----
            c.bench_function(&format!("AVX2 INV-lazy q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| avx2_table.lazy_inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint32 INV-lazy q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| uint32_table.lazy_inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });

            // ---- Inverse: canonical ----
            c.bench_function(&format!("AVX2 INV-cano q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| avx2_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint32 INV-cano q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| uint32_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });

            // ---- Full pipeline: forward + inverse ----
            c.bench_function(&format!("AVX2 FWD+INV  q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| {
                        avx2_table.transform_slice(black_box(poly));
                        avx2_table.inverse_transform_slice(black_box(poly));
                    },
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint32 FWD+INV  q:{q:>9} n:{n:>5}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| {
                        uint32_table.transform_slice(black_box(poly));
                        uint32_table.inverse_transform_slice(black_box(poly));
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
