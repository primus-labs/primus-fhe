use algebra::{
    derive::*, Field, FieldBinarySampler, FieldDiscreteGaussianSampler, FieldTernarySampler,
    FieldUniformSampler, Polynomial, PrimeField,
};
use num_traits::{Inv, One, Pow, Zero};
use rand::prelude::*;

// Derive macro `Field` generates an impl of the trait `algebra::Field`.
//
// This also generates some computation for it, e.g.
// `Add`, `Sub`, `Mul`, `Neg`, `Pow`, `Div` and `Inv`.
//
// By the way, it also generates impl of the trait `Zero`, `One`, `Display`.
//
// And it will generate impl of the trait
// `Clone`, `Copy`, `Debug`, `Default`, `Eq`, `PartialEq`, `PartialOrd`, `Ord`.
//
// It can used for unnamed struct with only one element of `u8`, `u16`, `u32`, `u64`.

// Derive macro `Prime` generating an impl of the trait `algebra::PrimeField`.
//
// It's based the Derive macro `Field`.

// Derive macro `NTT` generating an impl of the trait `algebra::NTTField`.
//
// It's based the Derive macro `Prime`.

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct FF(u64);

fn main() -> Result<(), algebra::AlgebraError> {
    let mut rng = thread_rng();

    // You can generate a value by yourself
    let mut a = FF::new(9);
    // You can get the inner value by `get` function
    let a_in = a.value();
    assert_eq!(a_in, 9);
    // You can get the max value
    let mut b = FF::max();

    // you can get two special value `one` and `zero`
    let _one = FF::one();
    let _zero = FF::zero();
    let one = FF::one();
    let zero = FF::zero();

    // check `one` and `zero` by function
    assert!(one.is_one());
    assert!(zero.is_zero());

    // assign `one` and `zero` by function
    a.set_one();
    b.set_zero();

    // uniform random on all values of [`FF`]
    let uniform = <FieldUniformSampler<FF>>::new();
    let mut a = uniform.sample(&mut rng);

    // other distributions
    let _binary_sampler = FieldBinarySampler;
    let _ternary_sampler = FieldTernarySampler;
    let _gaussian_sampler = FieldDiscreteGaussianSampler::new(0.0, 3.2).unwrap();

    let b = loop {
        let t = uniform.sample(&mut rng);
        if !t.is_zero() {
            break t;
        }
    };

    // Some operation
    let _c = a + b;
    let _c = a - b;
    let _c = a * b;
    let _c = a / b;

    // Some assign operation
    a += b;
    a -= b;
    a *= b;
    a /= b;

    // neg operation
    a = -a;

    // inv operation
    a = a.inv(); // a = 1 / a;

    // pow operation
    a = a.pow(5);

    // you can print FF value by `Display` trait
    println!("a:{a}");

    // you can check whether the modulus is a prime number
    FF::is_prime_field();

    // through NTT, you can comput polynomial multiplication
    type PolyFF = Polynomial<FF>;
    const N: usize = 8;
    let a = PolyFF::random(N, &mut rng);
    let b = PolyFF::random(N, &mut rng);

    let _c = a * b;

    Ok(())
}
