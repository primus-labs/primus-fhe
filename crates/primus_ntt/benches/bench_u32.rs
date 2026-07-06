use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, Criterion};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable, UintNttTable};
use rand::distr::{Distribution, Uniform};

const CASES: [(u32, usize); 1] = [(268369921, 4096)];
const POOL_SIZE: usize = 16;

fn quick_criterion() -> Criterion {
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

fn bench_forward<T: NttTable<ValueT = u32>>(
    c: &mut Criterion,
    name: &str,
    table: &T,
    pool: &[Vec<u32>],
    pool_idx: &mut usize,
) {
    c.bench_function(name, |b| {
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

fn bench_inverse<T: NttTable<ValueT = u32>>(
    c: &mut Criterion,
    name: &str,
    table: &T,
    pool: &[Vec<u32>],
    pool_idx: &mut usize,
) {
    c.bench_function(name, |b| {
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

fn bench_monomial<T: NttTable<ValueT = u32>>(
    c: &mut Criterion,
    name: &str,
    table: &T,
    coeff: u32,
    degree: usize,
    values: &mut [u32],
) {
    c.bench_function(name, |b| {
        b.iter(|| table.transform_monomial(black_box(coeff), black_box(degree), black_box(values)))
    });
}

fn bench_monomial_one<T: NttTable<ValueT = u32>>(
    c: &mut Criterion,
    name: &str,
    table: &T,
    degree: usize,
    values: &mut [u32],
) {
    c.bench_function(name, |b| {
        b.iter(|| table.transform_coeff_one_monomial(black_box(degree), black_box(values)))
    });
}

fn bench_monomial_minus_one<T: NttTable<ValueT = u32>>(
    c: &mut Criterion,
    name: &str,
    table: &T,
    degree: usize,
    values: &mut [u32],
) {
    c.bench_function(name, |b| {
        b.iter(|| table.transform_coeff_minus_one_monomial(black_box(degree), black_box(values)))
    });
}

fn bench_all(c: &mut Criterion) {
    for (q, n) in CASES {
        if !(q - 1).is_multiple_of(2 * n as u32) {
            continue;
        }

        let modulus = BarrettModulus::new(q);
        let log_n = n.trailing_zeros();
        let distr = Uniform::new(0, q).unwrap();
        let pool = gen_input_pool(&distr, n);

        let u32_table = U32NttTable::new(log_n, modulus).unwrap();
        let uint_table = UintNttTable::<u32>::new(log_n, modulus).unwrap();
        let mut pool_idx = 0usize;

        bench_forward(
            c,
            &format!("U32NttTable FWD q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            &format!("U32NttTable INV q:{q} n:{n}"),
            &u32_table,
            &pool,
            &mut pool_idx,
        );
        bench_forward(
            c,
            &format!("UintNttTable<u32> FWD q:{q} n:{n}"),
            &uint_table,
            &pool,
            &mut pool_idx,
        );
        bench_inverse(
            c,
            &format!("UintNttTable<u32> INV q:{q} n:{n}"),
            &uint_table,
            &pool,
            &mut pool_idx,
        );

        // --- monomial benchmarks ---
        let coeff = q - 1; // non-trivial coeff
        let degree = n / 3; // non-trivial degree
        let mut values = vec![0u32; n];

        bench_monomial(
            c,
            &format!("U32NttTable MONO coeff:{coeff} deg:{degree} q:{q} n:{n}"),
            &u32_table,
            coeff,
            degree,
            &mut values,
        );
        bench_monomial_one(
            c,
            &format!("U32NttTable MONO_X^d deg:{degree} q:{q} n:{n}"),
            &u32_table,
            degree,
            &mut values,
        );
        bench_monomial_minus_one(
            c,
            &format!("U32NttTable MONO_-X^d deg:{degree} q:{q} n:{n}"),
            &u32_table,
            degree,
            &mut values,
        );

        bench_monomial(
            c,
            &format!("UintNttTable<u32> MONO coeff:{coeff} deg:{degree} q:{q} n:{n}"),
            &uint_table,
            coeff,
            degree,
            &mut values,
        );
        bench_monomial_one(
            c,
            &format!("UintNttTable<u32> MONO_X^d deg:{degree} q:{q} n:{n}"),
            &uint_table,
            degree,
            &mut values,
        );
        bench_monomial_minus_one(
            c,
            &format!("UintNttTable<u32> MONO_-X^d deg:{degree} q:{q} n:{n}"),
            &uint_table,
            degree,
            &mut values,
        );
    }
}

criterion::criterion_group! {
    name = benches;
    config = quick_criterion();
    targets = bench_all
}
criterion::criterion_main!(benches);
