#![allow(dead_code)]

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, Criterion};
use primus_modulus::BarrettModulus;
use primus_ntt::{Concrete32Table, NttTable, U32NttTable, UintNttTable};
use rand::distr::{Distribution, Uniform};

const SCALAR_CASES: [(u32, usize); 1] = [(268369921, 4096)];
const AVX2_CASES: [(u32, usize); 1] = SCALAR_CASES;
const AVX512_CASES: [(u32, usize); 1] = SCALAR_CASES;
const POOL_SIZE: usize = 16;

pub fn quick_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

fn gen_input_pool(distr: &Uniform<u32>, n: usize) -> Vec<Vec<u32>> {
    let mut rng = rand::rng();
    (0..POOL_SIZE)
        .map(|_| distr.sample_iter(&mut rng).take(n).collect())
        .collect()
}

fn bench_forward<T>(
    c: &mut Criterion,
    name: String,
    table: &T,
    pool: &[Vec<u32>],
    pool_idx: &mut usize,
) where
    T: NttTable<ValueT = u32>,
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
    pool: &[Vec<u32>],
    pool_idx: &mut usize,
) where
    T: NttTable<ValueT = u32>,
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

fn prepare(q: u32, n: usize) -> (U32NttTable, Vec<Vec<u32>>) {
    let modulus = BarrettModulus::new(q);
    let log_n = n.trailing_zeros();
    let distr = Uniform::new(0, q).unwrap();
    let pool = gen_input_pool(&distr, n);
    let table = U32NttTable::new(log_n, modulus).unwrap();
    (table, pool)
}

pub fn bench_scalar(c: &mut Criterion) {
    for (q, n) in SCALAR_CASES {
        if !(q - 1).is_multiple_of(2 * n as u32) {
            continue;
        }

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let (u32_table, pool) = prepare(q, n);
        let uint32_table = UintNttTable::<u32>::new(log_n, modulus).unwrap();
        let mut pool_idx = 0usize;

        bench_forward(
            c,
            format!("u32/scalar/U32Ntt FWD q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_forward(
            c,
            format!("u32/scalar/Uint32 FWD q:{q} n:{n}"),
            &uint32_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u32/scalar/U32Ntt INV q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u32/scalar/Uint32 INV q:{q} n:{n}"),
            &uint32_table,
            &pool,
            &mut pool_idx,
        );
    }
}

pub fn bench_avx2(c: &mut Criterion) {
    for (q, n) in AVX2_CASES {
        if !(q - 1).is_multiple_of(2 * n as u32) {
            continue;
        }

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let (u32_table, pool) = prepare(q, n);
        let concrete32_table = Concrete32Table::new(log_n, modulus).unwrap();
        let mut pool_idx = 0usize;

        bench_forward(
            c,
            format!("u32/avx2/U32Ntt FWD q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_forward(
            c,
            format!("u32/avx2/Concrete32 FWD q:{q} n:{n}"),
            &concrete32_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u32/avx2/U32Ntt INV q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u32/avx2/Concrete32 INV q:{q} n:{n}"),
            &concrete32_table,
            &pool,
            &mut pool_idx,
        );
    }
}

pub fn bench_avx512(c: &mut Criterion) {
    for (q, n) in AVX512_CASES {
        if !(q - 1).is_multiple_of(2 * n as u32) {
            continue;
        }

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let (u32_table, pool) = prepare(q, n);
        let concrete32_table = Concrete32Table::new(log_n, modulus).unwrap();
        let mut pool_idx = 0usize;

        bench_forward(
            c,
            format!("u32/avx512/U32Ntt FWD q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_forward(
            c,
            format!("u32/avx512/Concrete32 FWD q:{q} n:{n}"),
            &concrete32_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u32/avx512/U32Ntt INV q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            format!("u32/avx512/Concrete32 INV q:{q} n:{n}"),
            &concrete32_table,
            &pool,
            &mut pool_idx,
        );
    }
}
