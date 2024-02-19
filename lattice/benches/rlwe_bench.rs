use algebra::{derive::*, Polynomial, Random};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lattice::RLWE;

#[derive(Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct FF(u32);

const M: usize = 1024;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let ff_dis = FF::standard_distribution();

    let a0 = <Polynomial<FF>>::random_with_dis(M, &mut rng, ff_dis);
    let a1 = <Polynomial<FF>>::random_with_dis(M, &mut rng, ff_dis);

    let b0 = <Polynomial<FF>>::random_with_dis(M, &mut rng, ff_dis);
    let b1 = <Polynomial<FF>>::random_with_dis(M, &mut rng, ff_dis);

    let mut c0 = <RLWE<FF>>::new(a0, b0);
    let c1 = <RLWE<FF>>::new(a1, b1);

    c.bench_function("RLWE extract", |b| b.iter(|| black_box(&c0).extract_lwe()));

    let mut group = c.benchmark_group("Ring Learning with error");

    group.bench_function("RLWE add element wise clone", |b| {
        b.iter(|| black_box(&c0).clone().add_element_wise(black_box(&c1)))
    });

    group.bench_function("RLWE add element wise collect", |b| {
        b.iter(|| black_box(&c0).add_element_wise_ref(black_box(&c1)))
    });

    group.bench_function("RLWE sub element wise clone", |b| {
        b.iter(|| black_box(&c0).clone().sub_element_wise(black_box(&c1)))
    });

    group.bench_function("RLWE sub element wise collect", |b| {
        b.iter(|| black_box(&c0).sub_element_wise_ref(black_box(&c1)))
    });

    group.bench_function("RLWE add inplace element wise", |b| {
        b.iter(|| black_box(&mut c0).add_assign_element_wise(black_box(&c1)))
    });

    group.bench_function("RLWE sub inplace element wise", |b| {
        b.iter(|| black_box(&mut c0).sub_assign_element_wise(black_box(&c1)))
    });

    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
