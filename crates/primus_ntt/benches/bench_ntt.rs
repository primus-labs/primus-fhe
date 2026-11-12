// Run all benchmarks:
// cargo bench -p primus_ntt --bench bench_ntt
//
// Filter by value type or operation, for example:
// cargo bench -p primus_ntt --bench bench_ntt -- "monomial/u64"
// cargo bench -p primus_ntt --bench bench_ntt -- "^ntt/u64/.*/forward/specialized$"
// cargo bench -p primus_ntt --bench bench_ntt -- "construction"
// cargo bench -p primus_ntt --bench bench_ntt --features parallel -- "dcrt_prefix"

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, BenchmarkGroup, BenchmarkId, Criterion, measurement::WallTime};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
#[cfg(feature = "parallel")]
use primus_ntt::U64DcrtTable;
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable, UintNttTable};
use primus_shape::PolyLength;
use rand::{
    SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};

// Transform cases focus on representative workload and cache-working-set sizes.
// On machines without a given instruction set, the same cases measure the
// selected fallback.
const U32_AUXILIARY_CASE: (u32, usize) = (268_369_921, 4096);
const U64_AUXILIARY_CASE: (u64, usize) = (1_125_899_906_826_241, 4096);
const U32_TRANSFORM_CASES: &[(u32, usize)] =
    &[(132_120_577, 1024), (268_369_921, 1024), U32_AUXILIARY_CASE];
const U64_TRANSFORM_CASES: &[(u64, usize)] = &[
    // Below 2^30: IFMA or DQ-32 when available.
    (1_073_692_673, 1024),
    // Below 2^50: IFMA when available.
    (1_125_899_906_826_241, 1024),
    U64_AUXILIARY_CASE,
    (1_125_899_906_826_241, 8192),
    // Above the IFMA limit: AVX-512 DQ-64 when available.
    (1_152_921_504_606_830_593, 1024),
    (1_152_921_504_606_830_593, 8192),
];

const INPUT_POOL_SIZE: usize = 16;

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

fn bench_auxiliary_case<Value, Specialized, Generic>(
    criterion: &mut Criterion,
    case: &str,
    nontrivial_coeff: Value,
    specialized: &Specialized,
    generic: &Generic,
    input_pool: &[Vec<Value>],
) where
    Value: FheUint,
    Specialized: MonomialNttTable<ValueT = Value>,
    Generic: MonomialNttTable<ValueT = Value>,
{
    let mut lazy_group = criterion.benchmark_group(format!("lazy_ntt/{case}"));
    bench_lazy_ntt_table(&mut lazy_group, "specialized", specialized, input_pool);
    bench_lazy_ntt_table(&mut lazy_group, "generic", generic, input_pool);
    lazy_group.finish();

    let n = specialized.poly_length().get();
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

fn bench_construction_case<Value, Specialized>(
    criterion: &mut Criterion,
    case: &str,
    poly_length: PolyLength,
    modulus: BarrettModulus<Value>,
) where
    Value: FheUint,
    Specialized: NttTable<ValueT = Value>,
{
    let mut group = criterion.benchmark_group(format!("construction/{case}"));
    group.bench_function("specialized", |b| {
        b.iter(|| {
            black_box(Specialized::new(black_box(poly_length), black_box(modulus)).unwrap());
        })
    });
    group.bench_function("generic", |b| {
        b.iter(|| {
            black_box(UintNttTable::new(black_box(poly_length), black_box(modulus)).unwrap());
        })
    });
    group.finish();
}

/// Construct both tables and one input pool per case. The auxiliary timings
/// reuse one representative case per word width.
fn bench_word<Value, Specialized>(
    criterion: &mut Criterion,
    cases: &[(Value, usize)],
    auxiliary_case: (Value, usize),
) where
    Value: FheUint,
    Specialized: MonomialNttTable<ValueT = Value>,
{
    for &(q, n) in cases {
        let modulus = BarrettModulus::new(q);
        let poly_length = PolyLength::new(n);
        let distribution = Uniform::new(Value::ZERO, q).unwrap();
        let input_pool = generate_input_pool(&distribution, n);
        let specialized = Specialized::new(poly_length, modulus).unwrap();
        let generic = UintNttTable::<Value>::new(poly_length, modulus).unwrap();
        let case = format!("u{}/q={q}/n={n}", Value::BITS);

        let mut group = criterion.benchmark_group(format!("ntt/{case}"));
        bench_ntt_table(&mut group, "specialized", &specialized, &input_pool);
        bench_ntt_table(&mut group, "generic", &generic, &input_pool);
        group.finish();
        if (q, n) == auxiliary_case {
            bench_construction_case::<Value, Specialized>(criterion, &case, poly_length, modulus);
            bench_auxiliary_case(
                criterion,
                &case,
                q / Value::as_from(3u8),
                &specialized,
                &generic,
                &input_pool,
            );
        }
    }
}

/// Compare the same checked prefix with one and four workers. Both timings
/// include entry to a prepared pool and leave input copying in batch setup.
#[cfg(feature = "parallel")]
fn bench_dcrt_prefix(criterion: &mut Criterion) {
    const N: usize = 4096;
    const PREFIX_LIMBS: usize = 4;
    let moduli = [
        65537,
        1_073_692_673,
        1_125_899_906_826_241,
        1_152_921_504_606_830_593,
        268_369_921,
    ];
    let pools = [1, 4].map(|workers| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.broadcast(|_| {});
        pool
    });
    let table = pools[0].install(|| {
        U64DcrtTable::new(PolyLength::new(N), &moduli.map(BarrettModulus::new)).unwrap()
    });
    let mut rng = StdRng::seed_from_u64(42);
    let mut coefficients = Vec::with_capacity(N * PREFIX_LIMBS);
    for &q in &moduli[..PREFIX_LIMBS] {
        coefficients.extend(Uniform::new(0, q).unwrap().sample_iter(&mut rng).take(N));
    }
    let mut transformed = coefficients.clone();
    pools[0].install(|| table.transform_prefix_slice(&mut transformed));

    let mut group =
        criterion.benchmark_group(format!("dcrt_prefix/u64/n={N}/limbs={PREFIX_LIMBS}"));
    for pool in &pools {
        let workers = format!("workers={}", pool.current_num_threads());
        for (operation, input, transform) in [
            (
                "forward",
                &coefficients,
                U64DcrtTable::transform_prefix_slice as fn(&U64DcrtTable, &mut [u64]),
            ),
            (
                "inverse",
                &transformed,
                U64DcrtTable::inverse_transform_prefix_slice,
            ),
        ] {
            group.bench_function(BenchmarkId::new(operation, &workers), |b| {
                b.iter_batched_ref(
                    || input.clone(),
                    |values| pool.install(|| transform(&table, black_box(values.as_mut_slice()))),
                    BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

fn bench_ntt(criterion: &mut Criterion) {
    bench_word::<u32, U32NttTable>(criterion, U32_TRANSFORM_CASES, U32_AUXILIARY_CASE);
    bench_word::<u64, U64NttTable>(criterion, U64_TRANSFORM_CASES, U64_AUXILIARY_CASE);
    #[cfg(feature = "parallel")]
    bench_dcrt_prefix(criterion);
}

criterion::criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1));
    targets = bench_ntt
}
criterion::criterion_main!(benches);
