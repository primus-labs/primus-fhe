// Run all benchmarks:
// cargo bench -p primus_ntt --bench bench_ntt
//
// Filter by value type or operation, for example:
// cargo bench -p primus_ntt --bench bench_ntt -- "monomial/u64"
// cargo bench -p primus_ntt --bench bench_ntt -- "^ntt/u64/.*/forward/specialized$"
// cargo bench -p primus_ntt --bench bench_ntt -- "construction"

use core::fmt::Display;
use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, BenchmarkGroup, BenchmarkId, Criterion, measurement::WallTime};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable, UintNttTable};
use primus_reduce::FieldContext;
use primus_shape::PolyLength;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};

// Transform cases focus on representative workload and cache-working-set sizes.
// On machines without a given instruction set, the same cases measure the
// selected fallback.
const U32_TRANSFORM_CASES: &[(u32, usize)] = &[
    (132_120_577, 1024),
    (132_120_577, 2048),
    (268_369_921, 1024),
    (268_369_921, 4096),
];
const U64_TRANSFORM_CASES: &[(u64, usize)] = &[
    // Below 2^30: IFMA or DQ-32 when available.
    (1_073_692_673, 1024),
    (1_073_692_673, 2048),
    (1_073_692_673, 4096),
    // Below 2^50: IFMA when available.
    (1_125_899_906_826_241, 1024),
    (1_125_899_906_826_241, 2048),
    (1_125_899_906_826_241, 4096),
    (1_125_899_906_826_241, 8192),
    // Above the IFMA limit: AVX-512 DQ-64 when available.
    (1_152_921_504_606_830_593, 1024),
    (1_152_921_504_606_830_593, 2048),
    (1_152_921_504_606_830_593, 4096),
    (1_152_921_504_606_830_593, 8192),
];

// Keep the more numerous construction, lazy, monomial, and expansion
// operations focused on one representative size per arithmetic range.
const U32_AUXILIARY_CASES: &[(u32, usize)] = &[(268_369_921, 4096)];
const U64_AUXILIARY_CASES: &[(u64, usize)] = &[
    (1_073_692_673, 4096),
    (1_125_899_906_826_241, 4096),
    (1_152_921_504_606_830_593, 4096),
];
const INPUT_POOL_SIZE: usize = 16;

#[derive(Clone, Copy)]
struct BenchCase<Value> {
    value_type: &'static str,
    modulus: Value,
    n: usize,
    nontrivial_coeff: Value,
}

fn quick_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
}

fn generate_input_pool<Value>(
    distribution: &impl Distribution<Value>,
    n: usize,
) -> Vec<Vec<Value>> {
    let mut rng = StdRng::seed_from_u64(42);
    (0..INPUT_POOL_SIZE)
        .map(|_| distribution.sample_iter(&mut rng).take(n).collect())
        .collect()
}

fn bench_transform<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    operation: &str,
    implementation: &str,
    table: &Table,
    input_pool: &[Vec<Value>],
    transform: impl Fn(&Table, &mut [Value]),
) where
    Value: FheUint,
    Table: NttTable<ValueT = Value>,
{
    let mut input_index = 0usize;
    group.bench_function(BenchmarkId::new(operation, implementation), |b| {
        b.iter_batched_ref(
            || {
                let input = input_pool[input_index % input_pool.len()].clone();
                input_index = input_index.wrapping_add(1);
                input
            },
            |input| transform(table, black_box(input.as_mut_slice())),
            BatchSize::SmallInput,
        )
    });
}

fn bench_ntt_table<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    table: &Table,
    input_pool: &[Vec<Value>],
) where
    Value: FheUint,
    Table: NttTable<ValueT = Value>,
{
    bench_transform(
        group,
        "forward",
        implementation,
        table,
        input_pool,
        NttTable::transform_slice,
    );
    bench_transform(
        group,
        "inverse",
        implementation,
        table,
        input_pool,
        NttTable::inverse_transform_slice,
    );
}

fn bench_lazy_ntt_table<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    table: &Table,
    input_pool: &[Vec<Value>],
) where
    Value: FheUint,
    Table: NttTable<ValueT = Value>,
{
    bench_transform(
        group,
        "forward",
        implementation,
        table,
        input_pool,
        NttTable::lazy_transform_slice,
    );
    bench_transform(
        group,
        "inverse",
        implementation,
        table,
        input_pool,
        NttTable::lazy_inverse_transform_slice,
    );
}

fn bench_inplace<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    operation: &str,
    implementation: &str,
    table: &Table,
    output: &mut [Value],
    transform: impl Fn(&Table, &mut [Value]),
) where
    Value: FheUint,
    Table: MonomialNttTable<ValueT = Value>,
{
    group.bench_function(BenchmarkId::new(operation, implementation), |b| {
        b.iter(|| transform(table, black_box(&mut *output)))
    });
}

fn bench_monomial_table<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    table: &Table,
    coeff: Value,
    degree: usize,
    output: &mut [Value],
) where
    Value: FheUint,
    Table: MonomialNttTable<ValueT = Value>,
{
    bench_inplace(
        group,
        "arbitrary_coeff",
        implementation,
        table,
        output,
        |table, output| {
            table.transform_monomial(black_box(coeff), black_box(degree), output);
        },
    );
    bench_inplace(
        group,
        "coeff_one",
        implementation,
        table,
        output,
        |table, output| {
            table.transform_coeff_one_monomial(black_box(degree), output);
        },
    );
    bench_inplace(
        group,
        "coeff_minus_one",
        implementation,
        table,
        output,
        |table, output| {
            table.transform_coeff_minus_one_monomial(black_box(degree), output);
        },
    );
}

fn bench_expansion_table<Value, Table>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    implementation: &str,
    table: &Table,
    output: &mut [Value],
) where
    Value: FheUint,
    Table: MonomialNttTable<ValueT = Value>,
{
    let n = output.len();
    let transform_count = n.trailing_zeros();
    let operation = format!("all_shifts_{transform_count}_transforms");
    bench_inplace(
        group,
        &operation,
        implementation,
        table,
        output,
        |table, output| {
            for shift in 0..transform_count {
                table.transform_coeff_one_monomial(black_box(2 * n - (1usize << shift)), output);
            }
        },
    );
}

fn bench_ntt_case<Value, Specialized, Generic>(
    criterion: &mut Criterion,
    value_type: &str,
    modulus: Value,
    n: usize,
    specialized: &Specialized,
    generic: &Generic,
    input_pool: &[Vec<Value>],
) where
    Value: FheUint + Display,
    Specialized: MonomialNttTable<ValueT = Value>,
    Generic: MonomialNttTable<ValueT = Value>,
{
    let case = format!("{value_type}/q={modulus}/n={n}");

    let mut ntt_group = criterion.benchmark_group(format!("ntt/{case}"));
    bench_ntt_table(&mut ntt_group, "specialized", specialized, input_pool);
    bench_ntt_table(&mut ntt_group, "generic", generic, input_pool);
    ntt_group.finish();
}

fn bench_auxiliary_case<Value, Specialized, Generic>(
    criterion: &mut Criterion,
    case: BenchCase<Value>,
    specialized: &Specialized,
    generic: &Generic,
    input_pool: &[Vec<Value>],
) where
    Value: FheUint + Display,
    Specialized: MonomialNttTable<ValueT = Value>,
    Generic: MonomialNttTable<ValueT = Value>,
{
    let BenchCase {
        value_type,
        modulus,
        n,
        nontrivial_coeff,
    } = case;
    let case = format!("{value_type}/q={modulus}/n={n}");

    let mut lazy_group = criterion.benchmark_group(format!("lazy_ntt/{case}"));
    bench_lazy_ntt_table(&mut lazy_group, "specialized", specialized, input_pool);
    bench_lazy_ntt_table(&mut lazy_group, "generic", generic, input_pool);
    lazy_group.finish();

    let degree = n / 3;
    let mut specialized_output = vec![Value::ZERO; n];
    let mut generic_output = vec![Value::ZERO; n];

    let mut monomial_group = criterion.benchmark_group(format!("monomial/{case}"));
    bench_monomial_table(
        &mut monomial_group,
        "specialized",
        specialized,
        nontrivial_coeff,
        degree,
        &mut specialized_output,
    );
    bench_monomial_table(
        &mut monomial_group,
        "generic",
        generic,
        nontrivial_coeff,
        degree,
        &mut generic_output,
    );
    monomial_group.finish();

    let mut expansion_group = criterion.benchmark_group(format!("expansion/{case}"));
    bench_expansion_table(
        &mut expansion_group,
        "specialized",
        specialized,
        &mut specialized_output,
    );
    bench_expansion_table(
        &mut expansion_group,
        "generic",
        generic,
        &mut generic_output,
    );
    expansion_group.finish();
}

fn bench_construction_case<Value, Specialized, Generic, Modulus>(
    criterion: &mut Criterion,
    value_type: &str,
    modulus: Value,
    n: usize,
    modulus_context: Modulus,
) where
    Value: FheUint + Display,
    Specialized: NttTable<ValueT = Value>,
    Generic: NttTable<ValueT = Value>,
    Modulus: Copy + FieldContext<Value>,
{
    let poly_length = PolyLength::new(n);
    let case = format!("{value_type}/q={modulus}/n={n}");
    let mut group = criterion.benchmark_group(format!("construction/{case}"));
    group.bench_function("specialized", |b| {
        b.iter(|| {
            black_box(
                Specialized::new(black_box(poly_length), black_box(modulus_context)).unwrap(),
            );
        })
    });
    group.bench_function("generic", |b| {
        b.iter(|| {
            black_box(Generic::new(black_box(poly_length), black_box(modulus_context)).unwrap());
        })
    });
    group.finish();
}

fn bench_u32(criterion: &mut Criterion) {
    for &(q, n) in U32_TRANSFORM_CASES {
        assert!((q - 1).is_multiple_of(2 * n as u32));

        let modulus = BarrettModulus::new(q);
        let poly_length = PolyLength::new(n);
        let distribution = Uniform::new(0, q).unwrap();
        let input_pool = generate_input_pool(&distribution, n);
        let specialized = U32NttTable::new(poly_length, modulus).unwrap();
        let generic = UintNttTable::<u32>::new(poly_length, modulus).unwrap();

        bench_ntt_case(criterion, "u32", q, n, &specialized, &generic, &input_pool);
    }

    for &(q, n) in U32_AUXILIARY_CASES {
        let modulus = BarrettModulus::new(q);
        let poly_length = PolyLength::new(n);
        let distribution = Uniform::new(0, q).unwrap();
        let input_pool = generate_input_pool(&distribution, n);
        let specialized = U32NttTable::new(poly_length, modulus).unwrap();
        let generic = UintNttTable::<u32>::new(poly_length, modulus).unwrap();

        bench_construction_case::<u32, U32NttTable, UintNttTable<u32>, _>(
            criterion, "u32", q, n, modulus,
        );
        bench_auxiliary_case(
            criterion,
            BenchCase {
                value_type: "u32",
                modulus: q,
                n,
                nontrivial_coeff: q / 3,
            },
            &specialized,
            &generic,
            &input_pool,
        );
    }
}

fn bench_u64(criterion: &mut Criterion) {
    for &(q, n) in U64_TRANSFORM_CASES {
        assert!((q - 1).is_multiple_of(2 * n as u64));

        let modulus = BarrettModulus::new(q);
        let poly_length = PolyLength::new(n);
        let distribution = Uniform::new(0, q).unwrap();
        let input_pool = generate_input_pool(&distribution, n);
        let specialized = U64NttTable::new(poly_length, modulus).unwrap();
        let generic = UintNttTable::<u64>::new(poly_length, modulus).unwrap();

        bench_ntt_case(criterion, "u64", q, n, &specialized, &generic, &input_pool);
    }

    for &(q, n) in U64_AUXILIARY_CASES {
        let modulus = BarrettModulus::new(q);
        let poly_length = PolyLength::new(n);
        let distribution = Uniform::new(0, q).unwrap();
        let input_pool = generate_input_pool(&distribution, n);
        let specialized = U64NttTable::new(poly_length, modulus).unwrap();
        let generic = UintNttTable::<u64>::new(poly_length, modulus).unwrap();

        bench_construction_case::<u64, U64NttTable, UintNttTable<u64>, _>(
            criterion, "u64", q, n, modulus,
        );
        bench_auxiliary_case(
            criterion,
            BenchCase {
                value_type: "u64",
                modulus: q,
                n,
                nontrivial_coeff: q / 3,
            },
            &specialized,
            &generic,
            &input_pool,
        );
    }
}

criterion::criterion_group! {
    name = benches;
    config = quick_criterion();
    targets = bench_u32, bench_u64
}
criterion::criterion_main!(benches);
