use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_modulus::BarrettModulus;
use primus_ntt::{
    Concrete32Table, Concrete64Table, HexlNttTable, NttTable, U32NttTable, U64NttTable,
    UintNttTable,
};
use rand::distr::{Distribution, Uniform};

/// u32 primes < 2^30.
const U32_PRIMES: &[u32] = &[132120577, 536813569];
/// u64 primes covering 32/52/64-bit regimes.
const U64_PRIMES: &[u64] = &[536813569, 562949953392641, 1152921504606830593];
/// Representative N values for HE workloads.
const NS: &[usize] = &[1024, 4096];
/// Number of pre-generated input batches to rotate through to avoid
/// re-sampling overhead in the setup closure.
const POOL_SIZE: usize = 16;

fn gen_input_pool_u32(distr: &Uniform<u32>, n: usize) -> Vec<Vec<u32>> {
    let mut rng = rand::rng();
    (0..POOL_SIZE)
        .map(|_| distr.sample_iter(&mut rng).take(n).collect())
        .collect()
}

fn gen_input_pool_u64(distr: &Uniform<u64>, n: usize) -> Vec<Vec<u64>> {
    let mut rng = rand::rng();
    (0..POOL_SIZE)
        .map(|_| distr.sample_iter(&mut rng).take(n).collect())
        .collect()
}

fn bench_u32(c: &mut Criterion) {
    for &q in U32_PRIMES {
        for &n in NS {
            if !(q - 1).is_multiple_of(2 * n as u32) {
                continue;
            }

            let modulus = BarrettModulus::new(q);
            let log_n = n.trailing_zeros();
            let distr = Uniform::new(0, q).unwrap();

            let u32_table = U32NttTable::new(log_n, modulus).unwrap();
            let uint32_table = UintNttTable::<u32>::new(log_n, modulus).unwrap();
            let concrete32_table = Concrete32Table::new(log_n, modulus).unwrap();

            let pool = gen_input_pool_u32(&distr, n);
            let mut pool_idx = 0usize;

            // Forward canonical
            c.bench_function(&format!("U32Ntt   FWD: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[pool_idx % POOL_SIZE].clone();
                        pool_idx += 1;
                        p
                    },
                    |poly| u32_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint32   FWD: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[pool_idx % POOL_SIZE].clone();
                        pool_idx += 1;
                        p
                    },
                    |poly| uint32_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Concr32  FWD: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[pool_idx % POOL_SIZE].clone();
                        pool_idx += 1;
                        p
                    },
                    |poly| concrete32_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });

            // Inverse canonical
            c.bench_function(&format!("U32Ntt   INV: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[pool_idx % POOL_SIZE].clone();
                        pool_idx += 1;
                        p
                    },
                    |poly| u32_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint32   INV: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[pool_idx % POOL_SIZE].clone();
                        pool_idx += 1;
                        p
                    },
                    |poly| uint32_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Concr32  INV: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[pool_idx % POOL_SIZE].clone();
                        pool_idx += 1;
                        p
                    },
                    |poly| concrete32_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

fn bench_u64(c: &mut Criterion) {
    for &q in U64_PRIMES {
        for &n in NS {
            if !(q - 1).is_multiple_of(2 * n as u64) {
                continue;
            }

            let modulus = BarrettModulus::new(q);
            let log_n = n.trailing_zeros();
            let distr = Uniform::new(0, q).unwrap();

            let u64_table = U64NttTable::new(log_n, modulus).unwrap();
            let uint64_table = UintNttTable::<u64>::new(log_n, modulus).unwrap();
            let hexl_table = HexlNttTable::new(log_n, modulus).unwrap();
            let concrete_table = Concrete64Table::new(log_n, modulus).unwrap();

            let pool = gen_input_pool_u64(&distr, n);
            let mut idx = 0usize;

            // Forward canonical
            c.bench_function(&format!("U64Ntt   FWD: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| u64_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint64   FWD: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| uint64_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Hexl     FWD: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| hexl_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Concrete FWD: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| concrete_table.transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });

            // Inverse canonical
            c.bench_function(&format!("U64Ntt   INV: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| u64_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Uint64   INV: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| uint64_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Hexl     INV: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| hexl_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
            c.bench_function(&format!("Concrete INV: q:{q} n:{n}"), |b| {
                b.iter_batched_ref(
                    || {
                        let p = pool[idx % POOL_SIZE].clone();
                        idx += 1;
                        p
                    },
                    |poly| concrete_table.inverse_transform_slice(black_box(poly)),
                    BatchSize::SmallInput,
                )
            });
        }
    }
}

criterion_group!(benches, bench_u32, bench_u64);
criterion_main!(benches);
