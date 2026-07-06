#![allow(dead_code)]

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, Criterion};
use primus_modulus::BarrettModulus;
use primus_ntt::{Concrete64Table, NttTable, U64NttTable, UintNttTable};
use rand::distr::{Distribution, Uniform};

const SCALAR_CASES: [(u64, usize); 2] = [(1073692673, 4096), (1125899906826241, 4096)];
const AVX2_CASES: [(u64, usize); 2] = SCALAR_CASES;
const AVX512_CASES: [(u64, usize); 2] = SCALAR_CASES;
const POOL_SIZE: usize = 16;

pub fn quick_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

fn gen_input_pool(distr: &Uniform<u64>, n: usize) -> Vec<Vec<u64>> {
    let mut rng = rand::rng();
    (0..POOL_SIZE)
        .map(|_| distr.sample_iter(&mut rng).take(n).collect())
        .collect()
}

fn bench_forward<T>(
    c: &mut Criterion,
    name: String,
    table: &T,
    pool: &[Vec<u64>],
    pool_idx: &mut usize,
) where
    T: NttTable<ValueT = u64>,
{
    c.bench_function(&name, |b| {
        b.iter_batched_ref(
            || {
                let p = pool[*pool_idx % POOL_SIZE].clone();
                *pool_idx += 1;
                p
            },
            |poly| table.transform_slice(black_box(poly.as_mut_slice())),
            BatchSize::SmallInput,
        )
    });
}

fn bench_inverse<T>(
    c: &mut Criterion,
    name: String,
    table: &T,
    pool: &[Vec<u64>],
    pool_idx: &mut usize,
) where
    T: NttTable<ValueT = u64>,
{
    c.bench_function(&name, |b| {
        b.iter_batched_ref(
            || {
                let p = pool[*pool_idx % POOL_SIZE].clone();
                *pool_idx += 1;
                p
            },
            |poly| table.inverse_transform_slice(black_box(poly.as_mut_slice())),
            BatchSize::SmallInput,
        )
    });
}

fn prepare(q: u64, n: usize) -> (U64NttTable, Vec<Vec<u64>>) {
    let modulus = BarrettModulus::new(q);
    let log_n = n.trailing_zeros();
    let distr = Uniform::new(0, q).unwrap();
    let pool = gen_input_pool(&distr, n);
    let table = U64NttTable::new(log_n, modulus).unwrap();
    (table, pool)
}

pub fn bench_scalar(c: &mut Criterion) {
    for (q, n) in SCALAR_CASES {
        if !(q - 1).is_multiple_of(2 * n as u64) {
            continue;
        }

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let (u64_table, pool) = prepare(q, n);
        let uint64_table = UintNttTable::<u64>::new(log_n, modulus).unwrap();
        let mut pool_idx = 0usize;

        bench_forward(
            c,
            format!("u64/scalar/U64Ntt FWD q:{q} n:{n}"),
            &u64_table,
            &pool,
            &mut pool_idx,
        );
        bench_forward(
            c,
            format!("u64/scalar/Uint64 FWD q:{q} n:{n}"),
            &uint64_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u64/scalar/U64Ntt INV q:{q} n:{n}"),
            &u64_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u64/scalar/Uint64 INV q:{q} n:{n}"),
            &uint64_table,
            &pool,
            &mut pool_idx,
        );
    }
}

pub fn bench_avx2(c: &mut Criterion) {
    for (q, n) in AVX2_CASES {
        if !(q - 1).is_multiple_of(2 * n as u64) {
            continue;
        }

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let (u64_table, pool) = prepare(q, n);
        let concrete64_table = Concrete64Table::new(log_n, modulus).unwrap();
        let mut pool_idx = 0usize;

        bench_forward(
            c,
            format!("u64/avx2/U64Ntt FWD q:{q} n:{n}"),
            &u64_table,
            &pool,
            &mut pool_idx,
        );
        bench_forward(
            c,
            format!("u64/avx2/Concrete64 FWD q:{q} n:{n}"),
            &concrete64_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u64/avx2/U64Ntt INV q:{q} n:{n}"),
            &u64_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u64/avx2/Concrete64 INV q:{q} n:{n}"),
            &concrete64_table,
            &pool,
            &mut pool_idx,
        );
    }
}

pub fn bench_avx512(c: &mut Criterion) {
    for (q, n) in AVX512_CASES {
        if !(q - 1).is_multiple_of(2 * n as u64) {
            continue;
        }

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let (u64_table, pool) = prepare(q, n);
        let concrete64_table = Concrete64Table::new(log_n, modulus).unwrap();
        let mut pool_idx = 0usize;

        bench_forward(
            c,
            format!("u64/avx512/U64Ntt FWD q:{q} n:{n}"),
            &u64_table,
            &pool,
            &mut pool_idx,
        );
        bench_forward(
            c,
            format!("u64/avx512/Concrete64 FWD q:{q} n:{n}"),
            &concrete64_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u64/avx512/U64Ntt INV q:{q} n:{n}"),
            &u64_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u64/avx512/Concrete64 INV q:{q} n:{n}"),
            &concrete64_table,
            &pool,
            &mut pool_idx,
        );
    }
}
