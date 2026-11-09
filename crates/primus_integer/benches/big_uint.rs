// cargo bench -p primus_integer --bench big_uint

mod support;

use core::{cmp::Ordering, hint::black_box};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::{BigUint, multiply_many_values};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use support::{RNG_SEED, random_values};

const BATCH_LEN: usize = 1024;
const LIMB_COUNTS: [usize; 2] = [2, 8];

fn bench_big_uint(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ 0x6269_675f_7569_6e74);
    let mut group = c.benchmark_group("big_uint");

    for limb_count in LIMB_COUNTS {
        let value_count = BATCH_LEN;
        let buffer_len = limb_count * value_count;
        let lhs = random_values::<u64>(&mut rng, buffer_len);
        let rhs = random_values::<u64>(&mut rng, buffer_len);
        let initial_acc = random_values::<u64>(&mut rng, buffer_len);
        let mut cmp_rhs = lhs.clone();
        for value in cmp_rhs.chunks_exact_mut(limb_count) {
            value[0] = value[0].wrapping_add(1);
        }
        // Ciphertext moduli are normally around 50--60 bits, while a gadget
        // decomposition digit is much smaller.
        let scalar = (rng.random::<u64>() & ((1u64 << 52) - 1)) | 1;
        let small_scalar = scalar & ((1u64 << 20) - 1);
        // Isolate the common no-carry path for scalar addition.
        let mut no_carry_lhs = lhs.clone();
        for value in no_carry_lhs.chunks_exact_mut(limb_count) {
            value[0] &= u64::MAX >> 1;
        }
        let case = format!("u64/{limb_count}_limbs");

        group.throughput(Throughput::Elements(value_count as u64));

        let mut product = vec![0u64; buffer_len];
        group.bench_function(BenchmarkId::new("mul_value_to", &case), |b| {
            b.iter(|| {
                let mut carry_mix = 0u64;
                let scalar = black_box(scalar);
                for (input, output) in black_box(lhs.as_slice())
                    .chunks_exact(limb_count)
                    .zip(black_box(product.as_mut_slice()).chunks_exact_mut(limb_count))
                {
                    carry_mix ^= BigUint(input).mul_value_to(scalar, &mut BigUint(output));
                }
                black_box(carry_mix)
            })
        });

        let mut acc = initial_acc.clone();
        group.bench_function(BenchmarkId::new("mul_value_add_to", &case), |b| {
            b.iter(|| {
                let mut carry_mix = 0u64;
                let scalar = black_box(scalar);
                for (input, acc) in black_box(lhs.as_slice())
                    .chunks_exact(limb_count)
                    .zip(black_box(acc.as_mut_slice()).chunks_exact_mut(limb_count))
                {
                    carry_mix ^= BigUint(input).mul_value_add_to(scalar, &mut BigUint(acc));
                }
                black_box(carry_mix)
            })
        });

        let mut value_sum = vec![0u64; buffer_len];
        group.bench_function(BenchmarkId::new("add_value_to_no_carry", &case), |b| {
            b.iter(|| {
                let mut carry_mix = false;
                let small_scalar = black_box(small_scalar);
                for (input, output) in black_box(no_carry_lhs.as_slice())
                    .chunks_exact(limb_count)
                    .zip(black_box(value_sum.as_mut_slice()).chunks_exact_mut(limb_count))
                {
                    carry_mix ^= BigUint(input).add_value_to(small_scalar, &mut BigUint(output));
                }
                black_box(carry_mix)
            })
        });

        let mut sum = vec![0u64; buffer_len];
        group.bench_function(BenchmarkId::new("add_to", &case), |b| {
            b.iter(|| {
                let mut carry_mix = false;
                for ((lhs, rhs), sum) in black_box(lhs.as_slice())
                    .chunks_exact(limb_count)
                    .zip(black_box(rhs.as_slice()).chunks_exact(limb_count))
                    .zip(black_box(sum.as_mut_slice()).chunks_exact_mut(limb_count))
                {
                    carry_mix ^= BigUint(lhs).add_to(&BigUint(rhs), &mut BigUint(sum));
                }
                black_box(carry_mix)
            })
        });

        let mut difference = vec![0u64; buffer_len];
        group.bench_function(BenchmarkId::new("sub_to", &case), |b| {
            b.iter(|| {
                let mut borrow_mix = false;
                for ((lhs, rhs), difference) in black_box(lhs.as_slice())
                    .chunks_exact(limb_count)
                    .zip(black_box(rhs.as_slice()).chunks_exact(limb_count))
                    .zip(black_box(difference.as_mut_slice()).chunks_exact_mut(limb_count))
                {
                    borrow_mix ^= BigUint(lhs).sub_to(&BigUint(rhs), &mut BigUint(difference));
                }
                black_box(borrow_mix)
            })
        });

        // Equal high limbs force comparison to scan the full fixed width.
        group.bench_function(BenchmarkId::new("cmp_full_scan", &case), |b| {
            b.iter(|| {
                let mut ordering_mix = 0usize;
                for (lhs, rhs) in black_box(lhs.as_slice())
                    .chunks_exact(limb_count)
                    .zip(black_box(cmp_rhs.as_slice()).chunks_exact(limb_count))
                {
                    ordering_mix ^= match BigUint(lhs).cmp(&BigUint(rhs)) {
                        Ordering::Less => 0,
                        Ordering::Equal => 1,
                        Ordering::Greater => 2,
                    };
                }
                black_box(ordering_mix)
            })
        });
    }

    // RNS base construction grows a product one modulus at a time. Keep this
    // allocation in the timed path because it is part of the public operation.
    const MODULI: [u64; 4] = [
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
        1_125_899_904_679_937,
    ];
    group.throughput(Throughput::Elements(MODULI.len() as u64));
    group.bench_function("multiply_many_values/u64/4_moduli", |b| {
        b.iter(|| black_box(multiply_many_values(black_box(&MODULI))))
    });

    group.finish();
}

criterion_group!(benches, bench_big_uint);
criterion_main!(benches);
