use algebra::{derive::*, Field, Polynomial, PrimeField, Random};
use num_traits::{Inv, One, Pow, Zero};
use rand::prelude::*;
use rand_distr::Standard;

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

// Derive macro `Random` generates an impl of the trait `algebra::Random`.
//
// Then you can use `rand` crate to generate numbers randomly.
//
// Besides the `Standard` and `Uniform` Distribution, you can also use the binary distribution,
// ternary distribution and gaussian distribution.

// Derive macro `Prime` generating an impl of the trait `algebra::PrimeField`.
//
// It's based the Derive macro `Field`.

// Derive macro `NTT` generating an impl of the trait `algebra::NTTField`.
//
// It's based the Derive macro `Prime`.

#[derive(Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct FF(u64);

fn main() -> Result<(), algebra::AlgebraError> {
    let mut rng = thread_rng();

    // You can generate a value by yourself
    let mut a = FF::new(9);
    // You can get the inner value by `get` function
    let a_in = a.get();
    assert_eq!(a_in, 9);
    // You can get the max value
    let mut b = FF::max();

    // you can get two special value `one` and `zero`
    let _one = FF::one();
    let _zero = FF::zero();
    let one = FF::ONE;
    let zero = FF::ZERO;

    // check `one` and `zero` by function
    assert!(one.is_one());
    assert!(zero.is_zero());

    // assign `one` and `zero` by function
    a.set_one();
    b.set_zero();

    // uniform random on all values of [`FF`]
    let mut a = FF::random(&mut rng);
    let b: FF = rand::random();
    let _a: FF = rng.gen();
    let _a: FF = Standard.sample(&mut rng);

    // custom uniform distribution
    let dis = rand::distributions::Uniform::new(FF(0), FF(64));
    let _a = dis.sample(&mut rng);

    // standard_distribution
    let _standard_distribution = FF::standard_distribution();
    // other distributions
    let _binary_distribution = FF::binary_sampler();
    let _ternary_distribution = FF::ternary_sampler();
    let _gaussian_distribution = FF::gaussian_sampler(0.0, 3.2)?;

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
