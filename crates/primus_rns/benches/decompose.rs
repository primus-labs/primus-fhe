use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_factor::{FactorBase, ShoupFactor};
use primus_modulus::BarrettModulus;
use primus_rns::{BaseConverter, RNSBase};

// Benchmarks intentionally focus on the slice-level APIs used by polynomial
// paths. Single-value compose/decompose is only a correctness primitive here.
type ValueT = u64;
type ModulusT = BarrettModulus<ValueT>;
type BaseT = RNSBase<ValueT, ModulusT>;

const POLY_LENGTH: usize = 4096;
const MODULI_2: &[ValueT] = &[1_125_899_906_826_241, 1_125_899_906_629_633];
const MODULI_3: &[ValueT] = &[137_438_822_401, 137_438_814_209, 137_438_773_249];

fn production_rns_base(moduli: &[ValueT]) -> BaseT {
    let moduli: Vec<_> = moduli.iter().copied().map(ModulusT::new).collect();
    RNSBase::new(&moduli).unwrap()
}

// Generate pseudo-random small values modulo small_modulus, used as input for
// wrapping_decompose and scaled-decompose benchmarks.
fn wrapping_values(value_count: usize, small_modulus: ValueT) -> Vec<ValueT> {
    (0..value_count)
        .map(|i| (i as ValueT * 37 + 11) % small_modulus)
        .collect()
}

// Generate deterministic CRT residues in modulus-major layout for benchmark
// input. Each modulus chunk is filled with fill patterns that are guaranteed
// to be within the corresponding modulus.
fn generated_crt_residues(base: &BaseT, value_count: usize) -> Vec<ValueT> {
    let mut residues = vec![0; base.moduli_count() * value_count];

    for (modulus_index, modulus) in base.moduli().iter().enumerate() {
        let modulus_value = modulus.value();
        for value_index in 0..value_count {
            residues[modulus_index * value_count + value_index] =
                (value_index as ValueT * 1_000_003 + (modulus_index as ValueT + 1) * 17)
                    % modulus_value;
        }
    }

    residues
}

// Compose CRT residues back into BigUint values for benchmark setup (needed
// as input to the decompose benchmarks).
fn compose_crt_residues(base: &BaseT, residues: &[ValueT], value_count: usize) -> Vec<ValueT> {
    let mut values = vec![0; base.big_uint_value_len() * value_count];
    let mut scratch = vec![0; base.moduli_count()];
    base.compose_multiple_values_to(residues, &mut values, value_count, &mut scratch);
    values
}

// Create per-modulus Shoup factors from deterministic values, used as scaling
// multipliers in the add_wrapping_decompose_small_values_scaled benchmark.
fn shoup_factors(base: &BaseT) -> Vec<ShoupFactor<ValueT>> {
    base.moduli()
        .iter()
        .enumerate()
        .map(|(i, modulus)| {
            let modulus_value = modulus.value();
            ShoupFactor::new(((i as ValueT + 3) * 17) % modulus_value, modulus_value)
        })
        .collect()
}

// Benchmark the five slice-level decompose/compose APIs used on polynomial
// paths: wrapping_decompose_small_values_to, add_wrapping_decompose_small_values_scaled,
// add_decompose_small_values_scaled, decompose_big_uint_values_to, and
// compose_multiple_values_to. Each is measured with two different modulus sets
// (2-modulus / 3-modulus) at POLY_LENGTH=4096.
fn bench_slice_decompose_and_compose(c: &mut Criterion) {
    let cases = [
        ("2mod/logB=18", MODULI_2, 1 << 18),
        ("3mod/logB=15", MODULI_3, 1 << 15),
    ];

    let mut group = c.benchmark_group("rns/slice_decompose_compose");
    group.throughput(Throughput::Elements(POLY_LENGTH as u64));

    for (label, moduli, small_modulus) in cases {
        let base = production_rns_base(moduli);
        let small_values = wrapping_values(POLY_LENGTH, small_modulus);
        let factors = shoup_factors(&base);

        let mut wrapping_out = vec![0; base.moduli_count() * POLY_LENGTH];
        group.bench_with_input(
            BenchmarkId::new("wrapping_decompose_small_values_to", label),
            &label,
            |b, _| {
                b.iter(|| {
                    base.wrapping_decompose_small_values_to(
                        black_box(&small_values),
                        black_box(&mut wrapping_out),
                        POLY_LENGTH,
                        black_box(small_modulus),
                    );
                });
            },
        );

        let mut acc = generated_crt_residues(&base, POLY_LENGTH);
        group.bench_with_input(
            BenchmarkId::new("add_wrapping_decompose_small_values_scaled", label),
            &label,
            |b, _| {
                b.iter(|| {
                    base.add_wrapping_decompose_small_values_scaled(
                        black_box(&small_values),
                        black_box(&mut acc),
                        POLY_LENGTH,
                        black_box(small_modulus),
                        black_box(&factors),
                    );
                });
            },
        );

        // Unsigned variant: same fused multiply-add without centered wrapping.
        // Use a fresh accumulator so we benchmark the same workload shape.
        let mut unsigned_acc = generated_crt_residues(&base, POLY_LENGTH);
        group.bench_with_input(
            BenchmarkId::new("add_decompose_small_values_scaled", label),
            &label,
            |b, _| {
                b.iter(|| {
                    base.add_decompose_small_values_scaled(
                        black_box(&small_values),
                        black_box(&mut unsigned_acc),
                        POLY_LENGTH,
                        black_box(&factors),
                    );
                });
            },
        );

        let crt_residues = generated_crt_residues(&base, POLY_LENGTH);
        let big_uint_values = compose_crt_residues(&base, &crt_residues, POLY_LENGTH);
        let mut decomposed = vec![0; crt_residues.len()];
        group.bench_with_input(
            BenchmarkId::new("decompose_big_uint_values_to", label),
            &label,
            |b, _| {
                b.iter(|| {
                    base.decompose_big_uint_values_to(
                        black_box(&big_uint_values),
                        black_box(&mut decomposed),
                        POLY_LENGTH,
                    );
                });
            },
        );

        let mut composed = vec![0; big_uint_values.len()];
        let mut scratch = vec![0; base.moduli_count()];
        group.bench_with_input(
            BenchmarkId::new("compose_multiple_values_to", label),
            &label,
            |b, _| {
                b.iter(|| {
                    base.compose_multiple_values_to(
                        black_box(&crt_residues),
                        black_box(&mut composed),
                        POLY_LENGTH,
                        black_box(&mut scratch),
                    );
                });
            },
        );
    }

    group.finish();
}

// Benchmark BaseConverter array APIs: fast_convert_array (3-modulus to 2-modulus,
// approximate correction) and exact_convert_array (3-modulus to 1-modulus,
// exact conversion). Both operate on POLY_LENGTH=4096 values.
fn bench_slice_base_convert(c: &mut Criterion) {
    let input_base = production_rns_base(MODULI_3);
    let output_base = production_rns_base(MODULI_2);
    let exact_output_moduli = [MODULI_2[0]];
    let exact_output_base = production_rns_base(&exact_output_moduli);

    let converter = BaseConverter::new(&input_base, &output_base);
    let exact_converter = BaseConverter::new(&input_base, &exact_output_base);
    let crt_in = generated_crt_residues(&input_base, POLY_LENGTH);

    let mut group = c.benchmark_group("rns/slice_base_convert");
    group.throughput(Throughput::Elements(POLY_LENGTH as u64));

    let mut fast_out = vec![0; output_base.moduli_count() * POLY_LENGTH];
    let mut fast_scratch = vec![0; input_base.moduli_count() * POLY_LENGTH];
    group.bench_function("fast_convert_array/3mod_to_2mod", |b| {
        b.iter(|| {
            converter.fast_convert_array(
                black_box(&crt_in),
                black_box(&mut fast_out),
                POLY_LENGTH,
                black_box(&mut fast_scratch),
            );
        });
    });

    let mut exact_out = vec![0; POLY_LENGTH];
    group.bench_function("exact_convert_array/3mod_to_1mod", |b| {
        b.iter(|| {
            exact_converter.exact_convert_array(
                black_box(&crt_in),
                black_box(&mut exact_out),
                POLY_LENGTH,
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_slice_decompose_and_compose,
    bench_slice_base_convert
);
criterion_main!(benches);
