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
    let mut rng = thread_rng();
    let sampler = <FieldUniformSampler<FF>>::new();

    // construct f
    let num_vars_f = 4;
    let f = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_f,
        field_vec!(FF; 4, 6, 7, 2, 7, 0, 1, 6, 3, 2, 1, 0, 4, 1, 1, 6),
    ));

    // construct t
    let num_vars_t = 3;
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_t,
        field_vec!(FF; 0, 1, 2, 3, 4, 5, 6, 7),
    ));

    // construct randomness
    let mut r = sampler.sample(&mut rng);
    while t[0] <= r && r <= t[(1 << num_vars_t) - 1] {
        r = sampler.sample(&mut rng);
    }
    let mut u: Vec<_> = (0..num_vars_f).map(|_| sampler.sample(&mut rng)).collect();
    u.push(r);
    let randomness = u;

    // construct instance
    let instance = LookupInstance::from_slice(&f, &t);
    let info = instance.info();

    // prove
    let (proof, oracle) = Lookup::prove(&instance, &randomness);

    // verify
    let subclaim = Lookup::verify(&proof, &info);
    assert!(subclaim.verify_subclaim(f, t, oracle, &randomness, &info));
}

#[test]
fn test_random_range_check() {
    let mut rng = thread_rng();
    let sampler = <FieldUniformSampler<FF>>::new();

    let num_vars_f = 16;
    let num_vars_t = 6;
    let range = 1 << num_vars_t;

    // construct f
    let f_evaluations: Vec<FF> = (0..(1 << num_vars_f))
        .map(|_| FF::new(rng.gen_range(0..range)))
        .collect();
    let f = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_f,
        f_evaluations,
    ));

    // construct t
    let t_evaluations: Vec<FF> = (0..range).map(FF::new).collect();
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_t,
        t_evaluations,
    ));

    // construct randomness
    let mut r = sampler.sample(&mut rng);
    while t[0] <= r && r <= t[(1 << num_vars_t) - 1] {
        r = sampler.sample(&mut rng);
    }
    let mut u: Vec<_> = (0..num_vars_f).map(|_| sampler.sample(&mut rng)).collect();
    u.push(r);
    let randomness = u;

    // construct instance
    let instance = LookupInstance::from_slice(&f, &t);
    let info = instance.info();

    // prove
    let (proof, oracle) = Lookup::prove(&instance, &randomness);

    // verify
    let subclaim = Lookup::verify(&proof, &info);
    assert!(subclaim.verify_subclaim(f, t, oracle, &randomness, &info));
}
