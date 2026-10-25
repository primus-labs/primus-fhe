//! Coefficient arithmetic: acc += first * X^r + second * X^s modulo X^N + 1.
//! Compare two single-term calls per polynomial with one paired batch call.
//! All modulus/word types use N=1024/2048 and batches of 1/8 polynomials, with
//! the same exponents and RNG seed. Barrett uses the same q at both widths;
//! native arithmetic wraps modulo 2^word_bits. Equal coefficient counts mean
//! u64 buffers contain twice as many bytes as u32 buffers.
//!
//! Each iteration adds one pair to an initialized accumulator, reusing all
//! buffers. No reset, allocation, transform or ciphertext workflow is timed.
//! Canonical outputs remain valid inputs for the next iteration.
//!
//! cargo bench -p primus_poly --bench monomial
//! Use -- --test to check all cases without collecting performance samples.

use std::{hint::black_box, time::Duration};

use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::{Polynomial, add_mul_monomial_pair_assign};
use primus_reduce::RingContext;
use rand::{SeedableRng, distr::Distribution, rngs::StdRng};

const Q: u32 = 132_120_577;

#[inline]
fn add_separately<T: FheUint, M: RingContext<T>>(
    acc: &mut [T],
    first: &[T],
    second: &[T],
    [r, s]: [usize; 2],
    n: usize,
    modulus: M,
) {
    for ((acc, first), second) in acc
        .chunks_exact_mut(n)
        .zip(first.chunks_exact(n))
        .zip(second.chunks_exact(n))
    {
        let mut acc = Polynomial(acc);
        acc.add_mul_monomial_assign(&Polynomial(first), r, modulus);
        acc.add_mul_monomial_assign(&Polynomial(second), s, modulus);
    }
}

fn bench_modulus<T: FheUint, M: RingContext<T>>(c: &mut Criterion, name: &str, modulus: M) {
    let uniform = modulus.uniform_distribution();
    for n in [1024, 2048] {
        for count in [1, 8] {
            let mut rng = StdRng::seed_from_u64(0x5035_6106);
            let mut sample = || {
                uniform
                    .sample_iter(&mut rng)
                    .take(count * n)
                    .collect::<Vec<_>>()
            };
            let first = sample();
            let second = sample();
            let mut separate_acc = vec![T::ZERO; count * n];
            let mut paired_acc = vec![T::ZERO; count * n];
            // Distinct, nonzero rotations; s also exercises the X^N = -1 sign.
            let [r, s] = [n / 3, n + 2 * n / 3];

            // Check this fixture before timing. Boundary cases and independent
            // ring-arithmetic validation live in tests/monomial.rs.
            add_separately(&mut separate_acc, &first, &second, [r, s], n, modulus);
            add_mul_monomial_pair_assign(&mut paired_acc, &first, r, &second, s, n, modulus);
            assert_eq!(separate_acc, paired_acc);

            let mut group = c.benchmark_group(format!("monomial/{name}/n{n}/batch{count}"));
            group.sampling_mode(SamplingMode::Flat);
            group.bench_function("separate", |b| {
                b.iter(|| {
                    add_separately(
                        black_box(&mut separate_acc),
                        black_box(&first),
                        black_box(&second),
                        black_box([r, s]),
                        black_box(n),
                        black_box(modulus),
                    );
                    black_box(&separate_acc);
                });
            });
            group.bench_function("paired", |b| {
                b.iter(|| {
                    add_mul_monomial_pair_assign(
                        black_box(&mut paired_acc),
                        black_box(&first),
                        black_box(r),
                        black_box(&second),
                        black_box(s),
                        black_box(n),
                        black_box(modulus),
                    );
                    black_box(&paired_acc);
                });
            });
            group.finish();
        }
    }
}

fn monomial(c: &mut Criterion) {
    bench_modulus::<u32, _>(c, "native/u32", NativeModulus::new());
    bench_modulus::<u64, _>(c, "native/u64", NativeModulus::new());
    bench_modulus(c, &format!("barrett/u32/q{Q}"), BarrettModulus::new(Q));
    bench_modulus(
        c,
        &format!("barrett/u64/q{Q}"),
        BarrettModulus::new(u64::from(Q)),
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = monomial
}
criterion_main!(benches);
