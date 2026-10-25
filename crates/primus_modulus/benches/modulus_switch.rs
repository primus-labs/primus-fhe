//! Fixed-pair scalar latency and batch throughput. Preparation and allocation
//! are outside timing; black-boxed state models a cached converter.
//! cargo bench -p primus_modulus --bench modulus_switch
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_modulus::integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::PrepareModulusSwitch;
use std::hint::black_box;

fn pair<T, S, D>(c: &mut Criterion, name: &str, source: S, target: D)
where
    T: FheUint,
    S: PrepareModulusSwitch<ValueT = T>,
    D: primus_modulus::reduce::Modulus<ValueT = T>,
{
    let switch = source.prepare_switch_to(target);
    let input: Vec<T> = (0..512u64)
        .map(|i| {
            let x = T::as_from(i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            source.explicit_value().map_or(x, |q| x % q)
        })
        .collect();
    let mut output = vec![T::ZERO; input.len()];
    let mut group = c.benchmark_group(format!("modulus_switch/u{}/{name}", T::BITS));
    group.bench_function("scalar", |b| {
        b.iter(|| black_box(&switch).switch(black_box(input[255])))
    });
    group.throughput(Throughput::Elements(input.len() as u64));
    group.bench_function(BenchmarkId::new("batch", input.len()), |b| {
        b.iter(|| {
            black_box(&switch).switch_map(
                black_box(&input)
                    .iter()
                    .copied()
                    .zip(black_box(&mut output)),
                |x, out| *out = x,
            );
        })
    });
    group.finish();
}

fn switches(c: &mut Criterion) {
    pair(
        c,
        "native_rotation",
        NativeModulus::<u32>::new(),
        PowOf2Modulus::new(2048),
    );
    pair(
        c,
        "power_of_two_expand",
        PowOf2Modulus::new(128u64),
        UintModulus::new(131),
    );
    pair(
        c,
        "barrett_rotation",
        BarrettModulus::new(132120577u32),
        PowOf2Modulus::new(2048),
    );
    pair(
        c,
        "barrett_rotation",
        BarrettModulus::new(1125899906826241u64),
        PowOf2Modulus::new(2048),
    );
    pair(
        c,
        "barrett_expand",
        BarrettModulus::new(1125899906826241u64),
        NativeModulus::new(),
    );
}

criterion_group!(benches, switches);
criterion_main!(benches);
