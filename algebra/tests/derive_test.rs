use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    modulus::BarrettModulus,
    reduce::*,
    Basis, DecomposableField, Field, FieldUniformSampler, ModulusConfig, PrimeField,
};
use num_traits::{Inv, One, Zero};
use rand::{distributions::Uniform, thread_rng, Rng};
use rand_distr::Distribution;

#[derive(Field, DecomposableField, FheField, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

type FF = Fp32;
type T = u32;
type W = u64;

#[test]
fn test_fp() {
    let p = FF::MODULUS.value();

    let distr = Uniform::new(0, p);
    let mut rng = thread_rng();

    assert!(FF::is_prime_field());

    // add
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = (a + b) % p;
    assert_eq!(FF::new(a) + FF::new(b), FF::new(c));

    // add_assign
    let mut a = FF::new(a);
    a += FF::new(b);
    assert_eq!(a, FF::new(c));

    // sub
    let a = rng.sample(distr);
    let b = rng.gen_range(0..=a);
    let c = (a - b) % p;
    assert_eq!(FF::new(a) - FF::new(b), FF::new(c));

    // sub_assign
    let mut a = FF::new(a);
    a -= FF::new(b);
    assert_eq!(a, FF::new(c));

    // mul
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = ((a as W * b as W) % p as W) as T;
    assert_eq!(FF::new(a) * FF::new(b), FF::new(c));

    // mul_assign
    let mut a = FF::new(a);
    a *= FF::new(b);
    assert_eq!(a, FF::new(c));

    // div
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let b_inv = b.exp_reduce(p - 2, BarrettModulus::<T>::new(p));
    let c = ((a as W * b_inv as W) % p as W) as T;
    assert_eq!(FF::new(a) / FF::new(b), FF::new(c));

    // div_assign
    let mut a = FF::new(a);
    a /= FF::new(b);
    assert_eq!(a, FF::new(c));

    // neg
    let a = rng.sample(distr);
    let a_neg = -FF::new(a);
    assert_eq!(FF::new(a) + a_neg, FF::zero());

    let a = FF::zero();
    assert_eq!(a, -a);

    // inv
    let a = rng.sample(distr);
    let a_inv = a.exp_reduce(p - 2, BarrettModulus::<T>::new(p));
    assert_eq!(FF::new(a).inv(), FF::new(a_inv));
    assert_eq!(FF::new(a) * FF::new(a_inv), FF::one());

    // associative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(
        (FF::new(a) + FF::new(b)) + FF::new(c),
        FF::new(a) + (FF::new(b) + FF::new(c))
    );
    assert_eq!(
        (FF::new(a) * FF::new(b)) * FF::new(c),
        FF::new(a) * (FF::new(b) * FF::new(c))
    );

    // commutative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    assert_eq!(FF::new(a) + FF::new(b), FF::new(b) + FF::new(a));
    assert_eq!(FF::new(a) * FF::new(b), FF::new(b) * FF::new(a));

    // identity
    let a = rng.sample(distr);
    assert_eq!(FF::new(a) + FF::new(0), FF::new(a));
    assert_eq!(FF::new(a) * FF::new(1), FF::new(a));

    // distribute
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(
        (FF::new(a) + FF::new(b)) * FF::new(c),
        (FF::new(a) * FF::new(c)) + (FF::new(b) * FF::new(c))
    );
}

#[test]
fn test_decompose() {
    const BITS: u32 = 2;
    const B: u32 = 1 << BITS;
    let basis = <Basis<Fp32>>::new(BITS);
    let rng = &mut thread_rng();

    let uniform = <FieldUniformSampler<FF>>::new();
    let a: FF = uniform.sample(rng);
    let decompose = a.decompose(basis);
    let compose = decompose
        .into_iter()
        .enumerate()
        .fold(FF::new(0), |acc, (i, d)| {
            acc + d * FF::new(B.pow(i as T) as T)
        });

    assert_eq!(compose, a);
}
