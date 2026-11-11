// cargo bench -p primus_integer --bench div_rem_scalar

use core::hint::black_box;

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use primus_integer::{DivRemScalar, DivWide, UnsignedInteger};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const LIMB_COUNTS: [usize; 2] = [2, 8];
const U128_HALF_WORD_DIVISOR: u128 = 0xdead_beef_cafe_babe;
const U128_FULL_WIDTH_DIVISOR: u128 = (1u128 << 96) | 0xc0ff_ee15_dead_beef;
const U128_DIVISORS: [(&str, u128); 2] = [
    ("half_word", U128_HALF_WORD_DIVISOR),
    ("full_width", U128_FULL_WIDTH_DIVISOR),
];

fn bench_barrett_division<T>(group: &mut BenchmarkGroup<'_, WallTime>, type_name: &str, divisor: T)
where
    T: UnsignedInteger,
{
    let dividend = [T::ZERO, T::ZERO, T::ONE];
    let mut quotient = [T::ZERO; 3];
    group.bench_function(BenchmarkId::new("barrett_reciprocal", type_name), |b| {
        b.iter(|| {
            let remainder = T::div_rem_scalar(
                black_box(&dividend),
                black_box(divisor),
                black_box(&mut quotient),
            );
            black_box(remainder)
        })
    });
}

fn bench_div_rem_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("div_rem_scalar");

    // Barrett precomputation divides 2^(2*BITS) by a word-sized modulus.
    bench_barrett_division(&mut group, "u32", 1_056_866_017u32);
    bench_barrett_division(&mut group, "u64", 1_125_899_906_826_241u64);

    // BFV plaintext scaling divides a dense RNS modulus product by a small
    // plaintext modulus. Two and eight limbs cover small and deep RNS bases.
    const PLAINTEXT_MODULUS: u64 = 65_537;
    let mut rng = StdRng::seed_from_u64(0x0d07_020c_140c_1d31);
    for limb_count in LIMB_COUNTS {
        let mut dividend = vec![0u64; limb_count];
        rng.fill(dividend.as_mut_slice());
        let mut quotient = vec![0u64; limb_count];
        let case = format!("u64/{limb_count}_limbs");

        group.bench_function(BenchmarkId::new("plaintext_scale", case), |b| {
            b.iter(|| {
                let remainder = u64::div_rem_scalar(
                    black_box(dividend.as_slice()),
                    black_box(PLAINTEXT_MODULUS),
                    black_box(quotient.as_mut_slice()),
                );
                black_box(remainder)
            })
        });
    }

    // u128 has separate half-word and Knuth-D kernels because no wider
    // primitive integer is available. Two and eight limbs expose both the
    // fixed setup cost and the per-limb cost of each kernel.
    for limb_count in LIMB_COUNTS {
        let mut dividend = vec![0u128; limb_count];
        rng.fill(dividend.as_mut_slice());
        let mut quotient = vec![0u128; limb_count];

        for (name, divisor) in U128_DIVISORS {
            group.bench_function(
                BenchmarkId::new(format!("u128_{name}"), format!("{limb_count}_limbs")),
                |b| {
                    b.iter(|| {
                        let remainder = u128::div_rem_scalar(
                            black_box(dividend.as_slice()),
                            black_box(divisor),
                            black_box(quotient.as_mut_slice()),
                        );
                        black_box(remainder)
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_div_wide(c: &mut Criterion) {
    let mut group = c.benchmark_group("div_wide");
    let lo = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef;
    for (name, divisor) in U128_DIVISORS {
        let hi = divisor - 1;
        group.bench_function(BenchmarkId::new("u128", name), |b| {
            b.iter(|| {
                black_box(u128::div_wide(
                    black_box(lo),
                    black_box(hi),
                    black_box(divisor),
                ))
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_div_rem_scalar, bench_div_wide);
criterion_main!(benches);
