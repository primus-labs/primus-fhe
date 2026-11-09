use primus_rns::{BaseConverter, RNSBase, ResidueFactors};
use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_factor::ShoupFactor;
use primus_modulus::BarrettModulus;

type Value = u64;
type Modulus = BarrettModulus<Value>;
type Base = RNSBase<Value, Modulus>;

const POLY_LENGTH: usize = 4096;
const MODULI_2: &[Value] = &[1_125_899_906_826_241, 1_125_899_906_629_633];
const MODULI_3: &[Value] = &[137_438_822_401, 137_438_814_209, 137_438_773_249];

fn base(moduli: &[Value]) -> Base {
    let moduli: Vec<_> = moduli.iter().copied().map(Modulus::new).collect();
    RNSBase::new(&moduli).unwrap()
}

fn wrapping_values(value_count: usize, small_modulus: Value) -> Vec<Value> {
    (0..value_count)
        .map(|index| (index as Value * 37 + 11) % small_modulus)
        .collect()
}

fn crt_residues(base: &Base, value_count: usize) -> Vec<Value> {
    let mut residues = vec![0; base.moduli_count() * value_count];
    for (modulus_index, (limb, modulus)) in residues
        .chunks_exact_mut(value_count)
        .zip(base.moduli())
        .enumerate()
    {
        let modulus = modulus.value();
        for (value_index, value) in limb.iter_mut().enumerate() {
            *value =
                (value_index as Value * 1_000_003 + (modulus_index as Value + 1) * 17) % modulus;
        }
    }
    residues
}

fn composed_values(base: &Base, residues: &[Value], value_count: usize) -> Vec<Value> {
    let mut values = vec![0; base.big_uint_value_len() * value_count];
    let mut scratch = vec![0; base.moduli_count()];
    base.compose_big_uint_values_to(residues, &mut values, value_count, &mut scratch);
    values
}

fn shoup_factors(base: &Base) -> ResidueFactors<Vec<ShoupFactor<Value>>> {
    ResidueFactors(
        base.moduli()
            .iter()
            .enumerate()
            .map(|(index, modulus)| {
                let modulus = modulus.value();
                ShoupFactor::new(((index as Value + 3) * 17) % modulus, modulus)
            })
            .collect(),
    )
}

// These are the allocation-free slice operations used by polynomial paths.
fn bench_base_slice_operations(c: &mut Criterion) {
    let cases = [
        ("2mod/logB=18", MODULI_2, 1 << 18),
        ("3mod/logB=15", MODULI_3, 1 << 15),
    ];
    let mut group = c.benchmark_group("rns/slice_decompose_compose");
    group.throughput(Throughput::Elements(POLY_LENGTH as u64));

    for (label, moduli, small_modulus) in cases {
        let base = base(moduli);
        let small_values = wrapping_values(POLY_LENGTH, small_modulus);
        let factors = shoup_factors(&base);

        let mut output = vec![0; base.moduli_count() * POLY_LENGTH];
        group.bench_function(
            BenchmarkId::new("wrapping_decompose_small_values_to", label),
            |b| {
                b.iter(|| {
                    base.wrapping_decompose_small_values_to(
                        black_box(&small_values),
                        black_box(&mut output),
                        black_box(small_modulus),
                    );
                });
            },
        );

        let mut wrapping_acc = crt_residues(&base, POLY_LENGTH);
        group.bench_function(
            BenchmarkId::new("add_wrapping_decompose_small_values_scaled_assign", label),
            |b| {
                b.iter(|| {
                    base.add_wrapping_decompose_small_values_scaled_assign(
                        black_box(&small_values),
                        black_box(&mut wrapping_acc),
                        black_box(small_modulus),
                        black_box(factors.view()),
                    );
                });
            },
        );

        let mut unsigned_acc = crt_residues(&base, POLY_LENGTH);
        group.bench_function(
            BenchmarkId::new("add_decompose_small_values_scaled_assign", label),
            |b| {
                b.iter(|| {
                    base.add_decompose_small_values_scaled_assign(
                        black_box(&small_values),
                        black_box(&mut unsigned_acc),
                        black_box(factors.view()),
                    );
                });
            },
        );

        let residues = crt_residues(&base, POLY_LENGTH);
        let values = composed_values(&base, &residues, POLY_LENGTH);
        let mut decomposed = vec![0; residues.len()];
        group.bench_function(
            BenchmarkId::new("decompose_big_uint_values_to", label),
            |b| {
                b.iter(|| {
                    base.decompose_big_uint_values_to(
                        black_box(&values),
                        black_box(&mut decomposed),
                        POLY_LENGTH,
                    );
                });
            },
        );

        let mut composed = vec![0; values.len()];
        let mut scratch = vec![0; base.moduli_count()];
        group.bench_function(BenchmarkId::new("compose_big_uint_values_to", label), |b| {
            b.iter(|| {
                base.compose_big_uint_values_to(
                    black_box(&residues),
                    black_box(&mut composed),
                    POLY_LENGTH,
                    black_box(&mut scratch),
                );
            });
        });
    }

    group.finish();
}

fn bench_base_conversion(c: &mut Criterion) {
    let input_base = base(MODULI_3);
    let output_base = base(MODULI_2);
    let corrected_output_base = base(&MODULI_2[..1]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let corrected_converter = BaseConverter::new(&input_base, &corrected_output_base);
    let input = crt_residues(&input_base, POLY_LENGTH);

    let mut group = c.benchmark_group("rns/slice_base_convert");
    group.throughput(Throughput::Elements(POLY_LENGTH as u64));

    let mut fast_output = vec![0; output_base.moduli_count() * POLY_LENGTH];
    let mut fast_scratch = vec![0; converter.fast_convert_array_scratch_len(POLY_LENGTH)];
    group.bench_function("fast_convert_array/3mod_to_2mod", |b| {
        b.iter(|| {
            converter.fast_convert_array(
                black_box(&input),
                black_box(&mut fast_output),
                POLY_LENGTH,
                black_box(&mut fast_scratch),
            );
        });
    });

    let mut corrected_output = vec![0; POLY_LENGTH];
    let mut corrected_workspace = corrected_converter.corrected_conversion_workspace(POLY_LENGTH);
    group.bench_function("corrected_convert_array/3mod_to_1mod", |b| {
        b.iter(|| {
            corrected_converter.corrected_convert_array(
                black_box(&input),
                black_box(&mut corrected_output),
                POLY_LENGTH,
                black_box(&mut corrected_workspace),
            );
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = bench_base_slice_operations, bench_base_conversion
}
criterion_main!(benches);
