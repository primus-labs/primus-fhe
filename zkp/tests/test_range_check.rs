use algebra::{
    derive::{DecomposableField, Field, Prime},
    BabyBear, BabyBearExetension, DenseMultilinearExtension, Field,
};
use fhe_core::{DefaultExtendsionFieldU32x4, DefaultFieldU32};
use num_traits::Zero;
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::prelude::*;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{Lookup, LookupInstance, LookupSnarks};

type FF = DefaultFieldU32;
type EF = DefaultExtendsionFieldU32x4;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

// #[derive(Field, DecomposableField, Prime)]
// #[modulus = 132120577]
// pub struct Fp32(u32);
// // field type
// type FF = Fp32;

#[derive(Field, DecomposableField, Prime)]
#[modulus = 59]
pub struct Fq(u32);

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

    let num_vars = 4;
    let block_size = 2;
    let range: usize = 6;

    // construct a trivial example

    let f0 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 4, 5, 2, 3, 0, 1, 1, 3, 2, 1, 0, 4, 1, 1, 0),
    ));
    let f1 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 2, 5, 3, 4, 0, 1, 4, 3, 2, 1, 0, 4, 1, 1, 3),
    ));
    let f2 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 5, 1, 2, 3, 0, 1, 1, 3, 2, 1, 0, 4, 1, 1, 1),
    ));
    let f3 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 5, 5, 2, 4, 0, 1, 2, 3, 2, 1, 0, 3, 1, 1, 1),
    ));
    let f4 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 1, 5, 2, 4, 0, 1, 3, 3, 2, 1, 0, 5, 1, 1, 2),
    ));

    let f_vec = vec![f0, f1, f2, f3, f4];

    let mut t_evaluations: Vec<_> = (0..range).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    // construct instance

    let mut instance = LookupInstance::<FF>::from_slice(&f_vec, t.clone(), block_size);
    let info = instance.info();

    let kit = Lookup::<FF>::prove(&mut instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = Lookup::<FF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_random_range_check() {
    // prepare parameters

    let num_vars = 8;
    let block_size = 4;
    let block_num = 5;
    let residual_size = 1;
    let lookup_num = block_num * block_size + residual_size;
    let range = 59;

    let mut rng = thread_rng();
    let f_vec: Vec<Rc<DenseMultilinearExtension<FF>>> = (0..lookup_num)
        .map(|_| {
            let f_evaluations: Vec<FF> = (0..(1 << num_vars))
                .map(|_| FF::new(rng.gen_range(0..range)))
                .collect();
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                f_evaluations,
            ))
        })
        .collect();

    let mut t_evaluations: Vec<_> = (0..range as usize).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    let mut instance = LookupInstance::from_slice(&f_vec, t.clone(), block_size);
    let info = instance.info();

    let kit = Lookup::<FF>::prove(&mut instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = Lookup::<FF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_snark() {
    // prepare parameters

    let num_vars = 8;
    let block_size = 4;
    let block_num = 5;
    let residual_size = 1;
    let lookup_num = block_num * block_size + residual_size;
    let range = 59;

    let mut rng = thread_rng();
    let f_vec: Vec<Rc<DenseMultilinearExtension<FF>>> = (0..lookup_num)
        .map(|_| {
            let f_evaluations: Vec<FF> = (0..(1 << num_vars))
                .map(|_| FF::new(rng.gen_range(0..range)))
                .collect();
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                f_evaluations,
            ))
        })
        .collect();

    let mut t_evaluations: Vec<_> = (0..range as usize).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    let instance = LookupInstance::from_slice(&f_vec, t.clone(), block_size);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <LookupSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}
