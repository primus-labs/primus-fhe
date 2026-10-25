//! Bounded signed-to-residue conversion used by secret-key backends.
//! cargo bench -p primus_modulus --bench signed_encoding

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::{AsFrom, FheUint};
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::EncodeSigned;

fn encode<T: FheUint>(c: &mut Criterion, name: &str, modulus: impl EncodeSigned<T>) {
    let mut group = c.benchmark_group(format!("slice/signed_encoding/{name}"));
    for length in [1024, 16384] {
        let mut state = 0x8356_125f_334d_aaaa_u64;
        let input: Vec<T::SignedInteger> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                T::SignedInteger::as_from((state % 77) as i64 - 38)
            })
            .collect();
        let mut output = vec![T::ZERO; length];
        group.throughput(Throughput::Elements(length as u64));
        group.bench_function(length.to_string(), |b| {
            b.iter(|| {
                black_box(modulus)
                    .encode_signed_slice_to(black_box(&input), black_box(&mut output));
            });
        });
    }
    group.finish();
}

fn benches(c: &mut Criterion) {
    encode(c, "native_u32", NativeModulus::<u32>::new());
    encode(c, "native_u64", NativeModulus::<u64>::new());
    encode(c, "pow_of_two_u32", PowOf2Modulus::new(1u32 << 27));
    encode(c, "pow_of_two_u64", PowOf2Modulus::new(1u64 << 50));
    encode(c, "barrett_u32", BarrettModulus::new(132_120_577u32));
    encode(
        c,
        "barrett_u64",
        BarrettModulus::new(1_125_899_906_826_241u64),
    );
}

criterion_group!(benchmarks, benches);
criterion_main!(benchmarks);
