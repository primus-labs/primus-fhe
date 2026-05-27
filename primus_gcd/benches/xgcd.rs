use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_gcd::Xgcd;
use rand::distr::{Distribution, Uniform};

type ValueT = u64;

fn bench_gcd(c: &mut Criterion) {
    let mut rng = rand::rng();

    // Low-MSB inputs: `[0, MAX>>1)` exercises the general `quot = u3 / v3`
    // path and the lower quot=1/2/3 short-circuits.
    let distr_lo = Uniform::new(0, ValueT::MAX >> 1).unwrap();
    // (larger, smaller) so x >= y for xgcd
    let data: Vec<(ValueT, ValueT)> = (0..1000)
        .map(|_| {
            let x = distr_lo.sample(&mut rng);
            let y = distr_lo.sample(&mut rng);
            (x.max(y), x.min(y))
        })
        .collect();

    // High-MSB inputs: `[MAX>>1 + 1, MAX]` triggers the "both operands have
    // top bit set" / "second MSB set" fast paths and lets us compare their
    // throughput against the general division path above.
    let distr_hi = Uniform::new((ValueT::MAX >> 1) + 1, ValueT::MAX).unwrap();
    let data_msb: Vec<(ValueT, ValueT)> = (0..1000)
        .map(|_| {
            let x = distr_hi.sample(&mut rng);
            let y = distr_hi.sample(&mut rng);
            (x.max(y), x.min(y))
        })
        .collect();

    c.bench_function("gcd", |b| {
        b.iter(|| {
            for &(x, y) in &data {
                black_box(black_box(x).gcd(black_box(y)));
            }
        })
    });

    c.bench_function("is_coprime", |b| {
        b.iter(|| {
            for &(x, y) in &data {
                black_box(black_box(x).is_coprime(black_box(y)));
            }
        })
    });

    c.bench_function("xgcd", |b| {
        b.iter(|| {
            for &(x, y) in &data {
                black_box(ValueT::xgcd(black_box(x), black_box(y)));
            }
        })
    });

    c.bench_function("xgcd_msb", |b| {
        b.iter(|| {
            for &(x, y) in &data_msb {
                black_box(ValueT::xgcd(black_box(x), black_box(y)));
            }
        })
    });

    c.bench_function("gcdinv", |b| {
        b.iter(|| {
            // gcdinv requires x < y, so swap the pair
            for &(larger, smaller) in &data {
                black_box(ValueT::gcdinv(black_box(smaller), black_box(larger)));
            }
        })
    });

    c.bench_function("gcdinv_msb", |b| {
        b.iter(|| {
            for &(larger, smaller) in &data_msb {
                black_box(ValueT::gcdinv(black_box(smaller), black_box(larger)));
            }
        })
    });

    // Odd low-MSB inputs for gcdinv_pow_of_2 / gcdinv_native (even inputs
    // return None immediately, which skews the measurement).
    let data_odd: Vec<ValueT> = data.iter().map(|&(x, _)| x | 1).collect();

    c.bench_function("gcdinv_pow_of_2 (mask=MAX)", |b| {
        b.iter(|| {
            for &a in &data_odd {
                black_box(ValueT::gcdinv_pow_of_2(
                    black_box(a),
                    black_box(ValueT::MAX),
                ));
            }
        })
    });

    c.bench_function("gcdinv_native", |b| {
        b.iter(|| {
            for &a in &data_odd {
                black_box(ValueT::gcdinv_native(black_box(a)));
            }
        })
    });

    // gcdinv_pow_of_2 with a smaller power-of-two modulus (16-bit).
    c.bench_function("gcdinv_pow_of_2 (mask=0xFFFF)", |b| {
        b.iter(|| {
            for &a in &data_odd {
                black_box(ValueT::gcdinv_pow_of_2(black_box(a), black_box(0xFFFF)));
            }
        })
    });
}

criterion_group!(benches, bench_gcd);
criterion_main!(benches);
