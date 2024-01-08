use algebra::{derive::*, Random};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lattice::LWE;
use rand::prelude::*;

#[derive(Ring, Random)]
#[modulus = 1024]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 1073692673]
pub struct FF(u32);

const N: usize = 512;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let rr_dis = RR::standard_distribution();

    let a0: Vec<RR> = rr_dis.sample_iter(&mut rng).take(N).collect();
    let a1: Vec<RR> = rr_dis.sample_iter(&mut rng).take(N).collect();

    let b0 = rr_dis.sample(&mut rng);
    let b1 = rr_dis.sample(&mut rng);

    let c0 = <LWE<RR>>::new(a0, b0);
    let c1 = <LWE<RR>>::new(a1, b1);

    c.bench_function("LWE add component wise clone", |b| {
        b.iter(|| black_box(&c0).clone().add_component_wise(black_box(&c1)))
    });

    c.bench_function("LWE add component wise collect", |b| {
        b.iter(|| black_box(&c0).ref_add_component_wise(black_box(&c1)))
    });

    c.bench_function("LWE sub component wise clone", |b| {
        b.iter(|| black_box(&c0).clone().sub_component_wise(black_box(&c1)))
    });

    c.bench_function("LWE sub component wise collect", |b| {
        b.iter(|| black_box(&c0).ref_sub_component_wise(black_box(&c1)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
