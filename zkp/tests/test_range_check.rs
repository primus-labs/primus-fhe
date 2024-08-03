use algebra::{
    derive::{DecomposableField, Field, Prime},
    DecomposableField, DenseMultilinearExtension, Field, FieldUniformSampler,
};
use num_traits::{One, Zero};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::{RangeCheck, RangeCheckInstance};

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

    let num_vars_f = 4;
    let f = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_f,
        field_vec!(FF; 4, 6, 7, 2, 7, 0, 1, 6, 3, 2, 1, 0, 4, 1, 1, 6),
    ));

    let num_vars_t = 3;
    let range = 1 << num_vars_t;
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars_t,
        field_vec!(FF; 0, 1, 2, 3, 4, 5, 6, 7),
    ));

    // compute the counting number m
    let mut m_evaluations = vec![Fp32::zero(); 1 << num_vars_t];
    f.iter().for_each(|x| {
        let idx: usize = x.value() as usize;
        m_evaluations[idx] += Fp32::one();
    });
    let m = DenseMultilinearExtension::from_evaluations_slice(num_vars_t, &m_evaluations);

    let mut r = sampler.sample(&mut rng);
    while t[0] <= r && r <= t[(1 << num_vars_t) - 1] {
        r = sampler.sample(&mut rng);
    }

    // compute t, inverse f and inverse t
    let f_inverse: DenseMultilinearExtension<Fp32> =
        DenseMultilinearExtension::from_evaluations_vec(
            num_vars_f,
            f.iter().map(|x_f| Fp32::one() / (r - x_f)).collect(),
        );
    let t_inverse: DenseMultilinearExtension<Fp32> =
        DenseMultilinearExtension::from_evaluations_vec(
            num_vars_t,
            t.iter()
                .zip(m.evaluations.iter())
                .map(|(x_t, x_m)| *x_m / (r - x_t))
                .collect(),
        );

    let instance = RangeCheckInstance::from_slice(&f, &f_inverse, &t_inverse, &m, range);
    let info = instance.info();

    let u: Vec<_> = (0..num_vars_f).map(|_| sampler.sample(&mut rng)).collect();

    let proof = RangeCheck::prove(&instance, &u, r);
    let subclaim = RangeCheck::verify(&proof, &info);
    assert!(subclaim.verify_subclaim(f, &f_inverse, &t_inverse, &t, &m, &u, r, &info));
}
