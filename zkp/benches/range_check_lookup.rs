use algebra::{
    derive::{DecomposableField, Field, Prime},
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use rand_distr::Distribution;
use std::cmp::max;
use std::rc::Rc;
use std::time::Duration;
use std::vec;
use zkp::piop::{Lookup, LookupInstance};

#[derive(Field, DecomposableField, Prime)]
#[modulus = 132120577]
pub struct Fp32(u32);

#[derive(Field, DecomposableField, Prime)]
#[modulus = 59]
pub struct Fq(u32);

// field type
type FF = Fp32;

pub fn criterion_benchmark(c: &mut Criterion) {
    let num_vars_f = 16;
    let block_size = 2;
    let block_num = 50;
    let lookup_num = block_num * block_size;
    let range = 59;

    // Generate random values
    // randomness here is not secure!
    let mut rng = thread_rng();
    let sampler = FieldUniformSampler::<FF>::new();
    let mut r = sampler.sample(&mut rng);
    while FF::new(0) <= r && r < FF::new(range) {
        r = sampler.sample(&mut rng);
    }
    let mut u: Vec<_> = (0..max(block_num, num_vars_f))
        .map(|_| sampler.sample(&mut rng))
        .collect();
    u.push(r);
    let randomness = u;

    let f_vec: Vec<Rc<DenseMultilinearExtension<Fp32>>> = (0..lookup_num)
        .map(|_| {
            let f_evaluations: Vec<FF> = (0..(1 << num_vars_f))
                .map(|_| FF::new(rng.gen_range(0..range)))
                .collect();
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars_f,
                f_evaluations,
            ))
        })
        .collect();

    let instance = LookupInstance::from_slice(&f_vec, range as usize, block_size);
    let info = instance.info();

    c.bench_function(
        &format!(
            "rang check proving time of lookup num {}, lookup size {}, range size {}",
            lookup_num,
            1 << num_vars_f,
            range
        ),
        |b| b.iter(|| Lookup::prove(&instance, &randomness)),
    );

    c.bench_function(
        &format!(
            "rang check verifying time of lookup num {}, lookup size {}, range size {}",
            lookup_num,
            1 << num_vars_f,
            range
        ),
        |b| {
            let (proof, oracle) = Lookup::prove(&instance, &randomness);
            b.iter(|| {
                let subclaim = Lookup::verify(&proof, &info);
                subclaim.verify_subclaim(f_vec.clone(), oracle.clone(), &randomness, &info);
            })
        },
    );
}

fn configure() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::new(5, 0))
        .measurement_time(Duration::new(10, 0))
        .sample_size(10)
}

criterion_group! {
    name = benches;
    config = configure();
    targets = criterion_benchmark
}

criterion_main!(benches);
