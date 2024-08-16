use algebra::{
    derive::{DecomposableField, Field, Prime},
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
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

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[test]
fn test_trivial_range_check() {
    // prepare parameters

    let num_vars_f = 4;
    let num_vars_t = 3;
    let block_size = 2;

    // construct randomness

    let mut rng = thread_rng();
    let sampler = <FieldUniformSampler<FF>>::new();
    let mut r = sampler.sample(&mut rng);
    while FF::new(0) <= r && r < FF::new(1 << num_vars_t) {
        r = sampler.sample(&mut rng);
    }
    let mut u: Vec<_> = (0..num_vars_f).map(|_| sampler.sample(&mut rng)).collect();
    u.push(r);
    let randomness = u;

    // construct a trivial example

    let f0 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_f,
        field_vec!(FF; 1, 6, 7, 2, 7, 0, 1, 6, 3, 2, 1, 0, 4, 1, 1, 6),
    ));
    let f1 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_f,
        field_vec!(FF; 4, 6, 7, 3, 7, 0, 1, 6, 3, 2, 1, 0, 4, 1, 1, 6),
    ));
    let f2 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_f,
        field_vec!(FF; 4, 6, 7, 2, 7, 0, 1, 1, 3, 2, 1, 0, 4, 1, 1, 6),
    ));
    let f3 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_f,
        field_vec!(FF; 4, 6, 5, 2, 7, 0, 1, 6, 3, 2, 1, 0, 7, 1, 1, 6),
    ));

    let f_vec = vec![f0, f1, f2, f3];

    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_t,
        field_vec!(FF; 0, 1, 2, 3, 4, 5, 6, 7),
    ));

    // construct instance

    let instance = LookupInstance::from_slice(&f_vec, &t, block_size);
    let info = instance.info();

    // prove

    let (proof, oracle) = Lookup::prove(&instance, &randomness);

    // verify

    let subclaim = Lookup::verify(&proof, &info);
    assert!(subclaim.verify_subclaim(f_vec, t, oracle, &randomness, &info));
}

#[test]
fn test_random_range_check() {
    // prepare parameters

    let num_vars_f = 16;
    let num_vars_t = 3;
    let block_size = 8;
    let block_num = 8;
    let lookup_num = block_num * block_size;
    let range = 1 << num_vars_t;

    // construct randomness

    let mut rng = thread_rng();
    let sampler = <FieldUniformSampler<FF>>::new();
    let mut r = sampler.sample(&mut rng);
    while FF::new(0) <= r && r < FF::new(1 << num_vars_t) {
        r = sampler.sample(&mut rng);
    }
    let mut u: Vec<_> = (0..num_vars_f).map(|_| sampler.sample(&mut rng)).collect();
    u.push(r);
    let randomness = u;

    // construct a random example

    let f_vec = (0..lookup_num)
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

    let t_evaluations: Vec<FF> = (0..range).map(FF::new).collect();
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_t,
        t_evaluations,
    ));

    // construct instance

    let instance = LookupInstance::from_slice(&f_vec, &t, block_size);
    let info = instance.info();

    // prove

    let (proof, oracle) = Lookup::prove(&instance, &randomness);

    // verify

    let subclaim = Lookup::verify(&proof, &info);
    assert!(subclaim.verify_subclaim(f_vec, t, oracle, &randomness, &info));
}