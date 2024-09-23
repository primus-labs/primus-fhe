use algebra::{
    derive::{DecomposableField, Field, Prime}, BabyBear, BabyBearExetension, Basis, DecomposableField, DenseMultilinearExtension, Field, FieldUniformSampler
};
use num_traits::{One, Zero};
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{
    AdditionInZq, AdditionInZqInstance, AdditionInZqPure, AdditionInZqSnarks,
    AdditionInZqSnarksOpt, DecomposedBitsInfo, Lookup,
};
#[derive(Field, DecomposableField, Prime)]
#[modulus = 59]
pub struct Fq(u32);

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[test]
fn test_trivial_addition_in_zq() {
    let q = FF::new(9);
    let base_len = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len = 4;
    let abc = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 4, 6, 8, 2),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 7, 3, 0, 1),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 2, 0, 8, 3),
        )),
    ];
    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 1, 0, 0),
    ));

    let bits_info = DecomposedBitsInfo::<FF> {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 3,
    };
    let instance = AdditionInZqInstance::<FF>::from_slice(&abc, &k, q, &bits_info);

    let info = instance.info();

    let kit = AdditionInZq::<FF>::prove(&instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = AdditionInZq::<FF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_random_addition_in_zq() {
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let base_len = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<Fq>>::new(base_len as u32).decompose_len();

    // Addition in Zq
    let a: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let b: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let c_k: Vec<_> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.value() + y.value() >= Fq::MODULUS_VALUE {
                (*x + *y, Fq::one())
            } else {
                (*x + *y, Fq::zero())
            }
        })
        .collect();

    let (c, k): (Vec<_>, Vec<_>) = c_k.iter().cloned().unzip();

    let abc = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            // Convert to Fp
            a.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            b.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            c.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
    ];

    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        k.iter().map(|x: &Fq| FF::new(x.value())).collect(),
    ));

    let bits_info = DecomposedBitsInfo::<FF> {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 3,
    };
    let instance = AdditionInZqInstance::<FF>::from_slice(&abc, &k, q, &bits_info);

    let info = instance.info();

    let kit = AdditionInZq::<FF>::prove(&instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = AdditionInZq::<FF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_random_addition_in_zq_extension_field() {
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let base_len = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<Fq>>::new(base_len as u32).decompose_len();

    // Addition in Zq
    let a: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let b: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let c_k: Vec<_> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.value() + y.value() >= Fq::MODULUS_VALUE {
                (*x + *y, Fq::one())
            } else {
                (*x + *y, Fq::zero())
            }
        })
        .collect();

    let (c, k): (Vec<_>, Vec<_>) = c_k.iter().cloned().unzip();

    let abc = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            // Convert to Fp
            a.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            b.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            c.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
    ];

    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        k.iter().map(|x: &Fq| FF::new(x.value())).collect(),
    ));

    let bits_info = DecomposedBitsInfo::<FF> {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 3,
    };
    let instance = AdditionInZqInstance::<FF>::from_slice(&abc, &k, q, &bits_info);

    let instance_ef = instance.to_ef::<EF>();
    let info = instance_ef.info();

    let kit = AdditionInZq::<EF>::prove(&instance_ef);
    let evals = instance.evaluate_ext(&kit.randomness);

    let wrapper = kit.extract();
    let check = AdditionInZq::<EF>::verify(&wrapper, &evals, &info);

    assert!(check);
}

#[test]
fn test_snarks() {
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let base_len = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<Fq>>::new(base_len as u32).decompose_len();

    // Addition in Zq
    let a: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let b: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let c_k: Vec<_> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.value() + y.value() >= Fq::MODULUS_VALUE {
                (*x + *y, Fq::one())
            } else {
                (*x + *y, Fq::zero())
            }
        })
        .collect();

    let (c, k): (Vec<_>, Vec<_>) = c_k.iter().cloned().unzip();

    let abc = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            // Convert to Fp
            a.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            b.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            c.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
    ];

    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        k.iter().map(|x: &Fq| FF::new(x.value())).collect(),
    ));

    let bits_info = DecomposedBitsInfo::<FF> {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 3,
    };
    let instance = AdditionInZqInstance::<FF>::from_slice(&abc, &k, q, &bits_info);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <AdditionInZqSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}

#[test]
fn test_trivial_addition_in_zq_with_lookup() {
    let q = FF::new(9);
    let base_len = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len = 4;
    let abc = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 4, 6, 8, 2),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 7, 3, 0, 1),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 2, 0, 8, 3),
        )),
    ];
    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 1, 0, 0),
    ));

    let bits_info = DecomposedBitsInfo::<FF> {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 3,
    };
    let instance = AdditionInZqInstance::<FF>::from_slice(&abc, &k, q, &bits_info);
    let mut lookup_instance = instance.extract_lookup_instance(1);

    let info = instance.info();
    let lookup_info = lookup_instance.info();

    let kit = AdditionInZqPure::<FF>::prove(&instance);
    let lookup_kit = Lookup::<FF>::prove(&mut lookup_instance);

    let evals = instance.evaluate(&kit.randomness);
    let lookup_evals = lookup_instance.evaluate(&lookup_kit.randomness);

    let wrapper = kit.extract();
    let lookup_wrapper = lookup_kit.extract();

    let check = AdditionInZqPure::<FF>::verify(&wrapper, &evals, &info);
    let lookup_check = Lookup::<FF>::verify(&lookup_wrapper, &lookup_evals, &lookup_info);

    assert!(check && lookup_check);
}

#[test]
fn test_trivial_addition_in_zq_with_lookup_snarks() {
    let q = FF::new(9);
    let base_len = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len = 4;
    let abc = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 4, 6, 8, 2),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 7, 3, 0, 1),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 2, 0, 8, 3),
        )),
    ];
    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 1, 0, 0),
    ));

    let bits_info = DecomposedBitsInfo::<FF> {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 3,
    };
    let instance = AdditionInZqInstance::<FF>::from_slice(&abc, &k, q, &bits_info);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <AdditionInZqSnarksOpt<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec, 1,
    );
}
