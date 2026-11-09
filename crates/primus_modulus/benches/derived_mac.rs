//! Run with `cargo bench -p primus_modulus --bench derived_mac --features derive`.
//! For portable-SIMD fallbacks, use
//! `cargo +nightly bench -p primus_modulus --bench derived_mac --features derive,simd`.

use core::{hint::black_box, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use primus_modulus::{Barrett, reduce::ReduceMulAddSlice};
use rand::{SeedableRng, distr::Distribution, distr::Uniform, rngs::StdRng};

// Compare the dispatched derive with its original constant-modulus fallback.
macro_rules! modulus_case {
    ($module:ident, $ty:ty, $q:literal) => {
        mod $module {
            use super::*;

            #[derive(Barrett)]
            #[modulus(ty = $ty, value = $q)]
            struct Modulus;

            #[inline]
            fn fallback(acc: &mut [$ty], lhs: &[$ty], rhs: &[$ty]) {
                #[cfg(not(feature = "simd"))]
                primus_modulus::common::compact::slice::reduce_add_mul_slice_assign(
                    Modulus, acc, lhs, rhs,
                );
                #[cfg(feature = "simd")]
                primus_modulus::common::compact::simd::reduce_add_mul_slice_assign::<
                    $ty,
                    Modulus,
                    primus_modulus::SimdBarrettModulus<$ty>,
                >(Modulus, acc, lhs, rhs);
            }

            #[inline]
            fn fallback_to(lhs: &[$ty], rhs: &[$ty], addend: &[$ty], output: &mut [$ty]) {
                #[cfg(not(feature = "simd"))]
                primus_modulus::common::compact::slice::reduce_mul_add_slice_to(
                    Modulus, lhs, rhs, addend, output,
                );
                #[cfg(feature = "simd")]
                primus_modulus::common::compact::simd::reduce_mul_add_slice_to::<
                    $ty,
                    Modulus,
                    primus_modulus::SimdBarrettModulus<$ty>,
                >(Modulus, lhs, rhs, addend, output);
            }

            pub(super) fn bench(c: &mut Criterion, lengths: &[usize]) {
                for &len in lengths {
                    let mut rng = StdRng::seed_from_u64(42);
                    let distribution = Uniform::new(0, Modulus::value()).unwrap();
                    let lhs: Vec<_> = distribution.sample_iter(&mut rng).take(len).collect();
                    let rhs: Vec<_> = distribution.sample_iter(&mut rng).take(len).collect();
                    let mut derived = lhs.clone();
                    let mut original = derived.clone();
                    let addend = derived.clone();
                    let mut output = vec![<$ty>::MAX; len];
                    let expected: Vec<_> = derived
                        .iter()
                        .zip(&lhs)
                        .zip(&rhs)
                        .map(|((&acc, &lhs), &rhs)| {
                            ((acc as u128 + lhs as u128 * rhs as u128) % Modulus::value() as u128)
                                as $ty
                        })
                        .collect();
                    Modulus.reduce_add_mul_slice_assign(&mut derived, &lhs, &rhs);
                    fallback(&mut original, &lhs, &rhs);
                    assert_eq!(derived, expected);
                    assert_eq!(original, expected);
                    Modulus.reduce_mul_add_slice_to(&lhs, &rhs, &addend, &mut output);
                    assert_eq!(output, expected);
                    fallback_to(&lhs, &rhs, &addend, &mut output);
                    assert_eq!(output, expected);

                    let mut group = c.benchmark_group(format!(
                        "barrett/derived_mac/{}/n{len}",
                        stringify!($module)
                    ));
                    group.bench_function("derived", |b| {
                        b.iter(|| {
                            Modulus.reduce_add_mul_slice_assign(
                                black_box(&mut derived),
                                black_box(&lhs),
                                black_box(&rhs),
                            )
                        })
                    });
                    group.bench_function("constant_fallback", |b| {
                        b.iter(|| {
                            fallback(black_box(&mut original), black_box(&lhs), black_box(&rhs))
                        })
                    });
                    group.bench_function("to", |b| {
                        b.iter(|| {
                            Modulus.reduce_mul_add_slice_to(
                                black_box(&lhs),
                                black_box(&rhs),
                                black_box(&addend),
                                black_box(&mut output),
                            )
                        })
                    });
                    group.bench_function("to_constant_fallback", |b| {
                        b.iter(|| {
                            fallback_to(
                                black_box(&lhs),
                                black_box(&rhs),
                                black_box(&addend),
                                black_box(&mut output),
                            )
                        })
                    });
                    group.finish();
                }
            }
        }
    };
}

modulus_case!(u16, u16, 12289);
modulus_case!(u32, u32, 132120577);
modulus_case!(u32_power_of_two, u32, 536870912);
modulus_case!(u64_small, u64, 1125899906826241);
modulus_case!(u64_power_of_two, u64, 281474976710656);
modulus_case!(u64_ifma_cutoff, u64, 1125899906842624);
modulus_case!(u64_large, u64, 4611686018427387903);

fn derived_mac(c: &mut Criterion) {
    u16::bench(c, &[1024]);
    u32::bench(c, &[17, 1024]);
    u32_power_of_two::bench(c, &[1024]);
    // Short lengths diagnose the native threshold and non-vector tails.
    u64_small::bench(c, &[17, 31, 32, 33, 1024]);
    u64_power_of_two::bench(c, &[1024]);
    u64_ifma_cutoff::bench(c, &[1024]);
    u64_large::bench(c, &[1024]);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = derived_mac
}
criterion_main!(benches);
