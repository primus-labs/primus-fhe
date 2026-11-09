// cargo bench -p primus_decompose --bench decompose
// cargo +nightly bench -p primus_decompose --bench decompose --features simd
//
// BigUint setup measures integer decomposition precomputation only. RNS
// reconstruction weights belong to primus_glwe_rns parameter construction.
// The generic online cases include initialization and every retained level.
// PBS cases use fixed external-product profiles and separate initialization,
// all retained levels, and their combined cost. They do not measure a full PBS.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::{big_integer::BigUintApproxSignedBasis, primitive::ApproxSignedBasis};
use primus_integer::{BigUint, FheUint, multiply_many_values};

type Word = u64;

const COEFFICIENT_COUNT: usize = 4096;
const PRIMITIVE_LOG_BASIS: u32 = 8;
const BIG_LOG_BASIS: u32 = 16;
const MODULI: [Word; 4] = [
    1_125_899_906_826_241,
    1_125_899_906_629_633,
    1_125_899_906_031_617,
    1_125_899_904_679_937,
];

fn big_modulus(limb_count: usize) -> BigUint<Vec<Word>> {
    multiply_many_values(&MODULI[..limb_count])
}

fn primitive_values(modulus: Option<Word>, count: usize) -> Vec<Word> {
    (0..count)
        .map(|index| {
            let value = (index as Word)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0xd1b5_4a32_d192_ed03);
            modulus.map_or(value, |q| value % q)
        })
        .collect()
}

fn big_values(modulus: BigUint<&[Word]>, count: usize) -> Vec<Word> {
    let len = modulus.len();
    let high_mask = Word::MAX >> modulus[len - 1].leading_zeros();
    let mut values = primitive_values(None, count * len);
    for digits in values.chunks_exact_mut(len) {
        // Limit inputs to the modulus bit width, then reduce once: 2^bits < 2Q.
        digits[len - 1] &= high_mask;
        let mut value = BigUint(digits);
        if value.cmp(&modulus).is_ge() {
            let _ = value.sub_assign(&modulus);
        }
    }
    values
}

fn bench_primitive_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/primitive/setup");
    for (label, modulus) in [("native", None), ("explicit_q50", Some(MODULI[0]))] {
        group.bench_function(
            BenchmarkId::new("new", format!("{label}/logB={PRIMITIVE_LOG_BASIS}")),
            |b| {
                b.iter(|| {
                    black_box(ApproxSignedBasis::<Word>::new(
                        black_box(modulus),
                        DecompositionBaseLog::new(PRIMITIVE_LOG_BASIS),
                        None,
                    ))
                });
            },
        );
    }
    group.finish();
}

fn bench_primitive_online(c: &mut Criterion) {
    // Native Fourier: exact and truncated, both using the no-copy carry path.
    primitive_online(c, "u64/native", None::<u64>, 8, None);
    primitive_online(c, "u64/native", None::<u64>, 8, Some(3));
    // Explicit moduli: adjustment with and without an initial rounding carry.
    primitive_online(c, "u64/q50", Some(MODULI[0]), 8, None);
    primitive_online(c, "u64/q50", Some(MODULI[0]), 10, None);
    // Representative NTT key-switching and external-product decompositions.
    primitive_online(c, "u32/q27", Some(132_120_577u32), 2, Some(13));
    primitive_online(c, "u32/q27", Some(132_120_577u32), 7, Some(3));
}

fn bench_pbs_decomposition(c: &mut Criterion) {
    // Fixed historical decomposition profiles, independent of the current
    // TFHE presets. N=1024/2048 cover common external-product polynomial lengths;
    // the labels identify the coefficient representation, not a current PBS config.
    for n in [1024, 2048] {
        pbs_decomposition(c, "glwe_ntt/u32", Some(132_120_577u32), 5, Some(5), n);
        pbs_decomposition(c, "glwe_ntt/u64", Some(MODULI[0]), 23, Some(1), n);
        pbs_decomposition(c, "ntru_ntt/u32", Some(132_120_577u32), 9, None, n);
        pbs_decomposition(c, "ntru_ntt/u64", Some(MODULI[0]), 9, None, n);
        pbs_decomposition(c, "glwe_fourier/u32", None::<u32>, 8, Some(3), n);
        pbs_decomposition(c, "glwe_fourier/u64", None::<u64>, 23, Some(1), n);
        pbs_decomposition(c, "ntru_fourier/u32", None::<u32>, 9, None, n);
        pbs_decomposition(c, "ntru_fourier/u64", None::<u64>, 9, None, n);
    }
}

fn pbs_decomposition<T: FheUint>(
    c: &mut Criterion,
    label: &str,
    modulus: Option<T>,
    log_basis: u32,
    retained: Option<usize>,
    n: usize,
) {
    let basis = ApproxSignedBasis::new(
        modulus,
        DecompositionBaseLog::new(log_basis),
        retained.map(DecompositionLevelCount::new),
    );
    // Fixed-seed xorshift covers the word range without a regular arithmetic stride.
    let mut state = 0x1234_5678_9abc_def0u64;
    let values: Vec<T> = (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = T::as_from(state);
            modulus.map_or(value, |q| value % q)
        })
        .collect();
    let mut adjusted = vec![T::ZERO; n];
    let mut carries = vec![false; n];
    let mut digits = vec![T::ZERO; n];
    let initialize = |adjusted: &mut [T], carries: &mut [bool]| {
        let basis = black_box(&basis);
        let values = black_box(&values);
        if modulus.is_some() {
            basis.init_value_carry_slice_to(values, adjusted, carries);
        } else {
            basis.init_carry_slice(values, carries);
        }
    };
    initialize(&mut adjusted, &mut carries);
    let initialized_carries = carries.clone();
    let input = if modulus.is_some() {
        &adjusted
    } else {
        &values
    };
    let (scalar_values, mut scalar_carries): (Vec<_>, Vec<_>) = values
        .iter()
        .map(|&value| basis.init_value_carry(value))
        .unzip();
    assert_eq!(input, &scalar_values);
    assert_eq!(carries, scalar_carries);
    for decomposer in basis.decomposer_iter() {
        decomposer.decompose_slice_to(input, &mut digits, &mut carries);
        for ((&value, &digit), (carry, &batch_carry)) in scalar_values
            .iter()
            .zip(&digits)
            .zip(scalar_carries.iter_mut().zip(&carries))
        {
            let (expected_digit, expected_carry) = decomposer.decompose(value, *carry);
            assert_eq!((digit, batch_carry), (expected_digit, expected_carry));
            *carry = expected_carry;
        }
    }

    let mut group = c.benchmark_group(format!(
        "decompose/pbs/{label}/logB={log_basis}/L={}/drop={}/N={n}",
        basis.level_count().get(),
        basis.drop_bits(),
    ));
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function("levels", |b| {
        // Restore the initial carry outside timing. Each timed invocation traverses
        // every level exactly once; carrying state across iterations would be invalid.
        b.iter_batched_ref(
            || initialized_carries.clone(),
            |carries| {
                for decomposer in black_box(&basis).decomposer_iter() {
                    decomposer.decompose_slice_to(
                        black_box(input),
                        black_box(&mut digits),
                        black_box(carries),
                    );
                    black_box(&digits);
                }
                black_box(carries);
            },
            BatchSize::PerIteration,
        );
    });
    group.bench_function("init", |b| {
        b.iter(|| {
            initialize(black_box(&mut adjusted), black_box(&mut carries));
            black_box((&adjusted, &carries));
        });
    });
    group.bench_function("full", |b| {
        b.iter(|| {
            initialize(black_box(&mut adjusted), black_box(&mut carries));
            let input = if modulus.is_some() {
                &adjusted
            } else {
                &values
            };
            for decomposer in black_box(&basis).decomposer_iter() {
                decomposer.decompose_slice_to(
                    black_box(input),
                    black_box(&mut digits),
                    black_box(&mut carries),
                );
                black_box(&digits);
            }
            black_box(&carries);
        });
    });
    group.finish();
}

fn primitive_online<T: FheUint>(
    c: &mut Criterion,
    label: &str,
    modulus: Option<T>,
    log_basis: u32,
    retained: Option<usize>,
) {
    let mut group = c.benchmark_group("decompose/primitive/online");
    let basis = ApproxSignedBasis::new(
        modulus,
        DecompositionBaseLog::new(log_basis),
        retained.map(DecompositionLevelCount::new),
    );
    let value = T::as_from(primitive_values(None, 1)[0]);
    let value = modulus.map_or(value, |q| value % q);
    group.bench_function(
        BenchmarkId::new(
            "scalar",
            format!(
                "{label}/logB={log_basis}/L={}/drop={}",
                basis.level_count().get(),
                basis.drop_bits()
            ),
        ),
        |b| {
            b.iter(|| {
                let (adjusted, mut carry) = basis.init_value_carry(black_box(value));
                for decomposer in basis.decomposer_iter() {
                    // LWE key switching uses the value-returning kernel;
                    // the batch cases below cover the output kernel.
                    let (digit, next_carry) = decomposer.decompose(adjusted, carry);
                    carry = next_carry;
                    black_box(digit);
                }
                black_box(carry)
            })
        },
    );
    let case = format!(
        "{label}/logB={log_basis}/L={}/drop={}/N={COEFFICIENT_COUNT}",
        basis.level_count().get(),
        basis.drop_bits(),
    );
    let values: Vec<T> = primitive_values(None, COEFFICIENT_COUNT)
        .into_iter()
        .map(|value| {
            let value = T::as_from(value);
            modulus.map_or(value, |q| value % q)
        })
        .collect();
    let mut decomposed = vec![T::ZERO; COEFFICIENT_COUNT];
    let mut carries = vec![false; COEFFICIENT_COUNT];
    group.throughput(Throughput::Elements(COEFFICIENT_COUNT as u64));
    // Select the initialization path outside the timed coefficient loops.
    if basis.modulus_is_power_of_2() {
        group.bench_function(BenchmarkId::new("batch_borrowed", &case), |b| {
            b.iter(|| {
                basis.init_carry_slice(black_box(&values), black_box(&mut carries));
                for decomposer in basis.decomposer_iter() {
                    decomposer.decompose_slice_to(
                        black_box(&values),
                        black_box(&mut decomposed),
                        black_box(&mut carries),
                    );
                    black_box(&decomposed);
                }
            });
        });
    } else {
        let mut adjusted = vec![T::ZERO; COEFFICIENT_COUNT];
        group.bench_function(BenchmarkId::new("batch_to", &case), |b| {
            b.iter(|| {
                basis.init_value_carry_slice_to(
                    black_box(&values),
                    black_box(&mut adjusted),
                    black_box(&mut carries),
                );
                for decomposer in basis.decomposer_iter() {
                    decomposer.decompose_slice_to(
                        black_box(&adjusted),
                        black_box(&mut decomposed),
                        black_box(&mut carries),
                    );
                    black_box(&decomposed);
                }
            });
        });
    }
    group.finish();
}

fn bench_big_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/big/setup");
    for limb_count in [1, 2, 4] {
        let modulus = big_modulus(limb_count);
        group.bench_function(
            BenchmarkId::new("new", format!("{limb_count}_limbs/logB={BIG_LOG_BASIS}")),
            |b| {
                b.iter(|| {
                    black_box(BigUintApproxSignedBasis::new(
                        black_box(modulus.view()),
                        DecompositionBaseLog::new(BIG_LOG_BASIS),
                        None,
                    ))
                });
            },
        );
    }
    group.finish();
}

fn bench_big_online(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/big/online");
    // Fixed strides 1/2/4 and the runtime-stride fallback (3); include no-drop,
    // cross-limb windows, and a truncated basis whose first window is in limb 1.
    for (limb_count, log_basis, retained) in [
        (1, 16, None),
        (2, 20, None),
        (3, 17, None),
        (4, 16, None),
        (2, 17, Some(1)),
    ] {
        let modulus = big_modulus(limb_count);
        let basis = BigUintApproxSignedBasis::new(
            modulus.view(),
            DecompositionBaseLog::new(log_basis),
            retained.map(DecompositionLevelCount::new),
        );
        let case = format!(
            "{limb_count}_limbs/logB={log_basis}/L={}/drop={}/N={COEFFICIENT_COUNT}",
            basis.level_count().get(),
            basis.drop_bits()
        );
        let values = big_values(modulus.view(), COEFFICIENT_COUNT);
        let mut adjusted = vec![0; values.len()];
        let mut digits = vec![0; COEFFICIENT_COUNT];
        let mut carries = vec![false; COEFFICIENT_COUNT];
        group.throughput(Throughput::Elements(COEFFICIENT_COUNT as u64));
        group.bench_function(BenchmarkId::new("batch_radix_to", &case), |b| {
            b.iter(|| {
                basis.init_value_carry_slice_to(
                    black_box(&values),
                    black_box(&mut adjusted),
                    black_box(&mut carries),
                );
                for decomposer in basis.decomposer_iter() {
                    decomposer.decompose_radix_slice_to(
                        black_box(&adjusted),
                        black_box(&mut digits),
                        black_box(&mut carries),
                    );
                    black_box(&digits);
                }
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = bench_primitive_setup, bench_primitive_online, bench_pbs_decomposition,
        bench_big_setup, bench_big_online
}
criterion_main!(benches);
