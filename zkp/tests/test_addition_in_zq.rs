use algebra::{
    derive::{Field, Prime, NTT},
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::{AdditionInZq, AdditionInZqInstance};

#[derive(Field, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

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
fn test_trivial_addition_in_zq() {
    let mut rng = thread_rng();
    let sampler = <FieldUniformSampler<FF>>::new();

    let q = FF::new(9);
    let base_len: u32 = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len: u32 = 4;
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

    // decompose bits of every element in a, b, c
    let abc_bits = abc
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();

    let abc_instance = AdditionInZqInstance::from_slice(&abc, &k, q, base, base_len, bits_len);
    let addition_info = abc_instance.info();

    let u: Vec<_> = (0..num_vars).map(|_| sampler.sample(&mut rng)).collect();

    let proof = AdditionInZq::prove(&abc_instance, &u);
    let subclaim = AdditionInZq::verify(&proof, &addition_info.decomposed_bits_info);
    assert!(subclaim.verify_subclaim(q, &abc, k.as_ref(), &abc_bits, &u, &addition_info));
}
