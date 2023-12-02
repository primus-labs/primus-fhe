use algebra::{
    derive::*,
    field::{Field, FieldDistribution, PrimeField},
    polynomial::Polynomial,
    ring::Ring,
};
use num_traits::{Inv, One, Pow, Zero};
use rand::{prelude::*, thread_rng};
use rand_distr::Standard;

// algebra's derive macro can used for unnamed struct with only one element of `u8`, `u16`, `u32`, `u64`.

// Derive macro `Ring` generating an impl of the trait `algebra::ring::Ring`.
//
// This also generating some compitation for it, e.g. `Add`, `Sub`, `Mul`, `Neg` and `Pow`.
//
// By the way, it also generating impl of the trait `Zero`, `One`, `Display`.
//
// But it will note generating impl of the trait `Clone`, `Copy`, `Debug`, `Default`, `Eq`, `PartialEq`, `PartialOrd`, `Ord`.
// You need to make it by yourself.

// Derive macro `Random` generating an impl of the trait `algebra::field::FieldDistribution`.
//
// Then you can use `rand` crate to generate it randomly.
//
// Besides the `Standard` and `Uniform` Distribution, you can also use the binary distribution,
// ternary distribution and normal distribution.

// Derive macro `Field` generating an impl of the trait `algebra::field::Field`.
//
// This also generating some compitation for it, e.g. `Div` and `Inv`.

// Derive macro `Prime` generating an impl of the trait `algebra::field::PrimeField`.
//
// It's based the Derive macro `Field`.

// Derive macro `NTT` generating an impl of the trait `algebra::field::NTTField`.
//
// It's based the Derive macro `Prime`.

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
)]
#[modulus = 132120577]
pub struct FF(u64);

fn main() -> Result<(), algebra::AlgebraError> {
    let mut rng = thread_rng();

    // You can generate a value by yourself
    let mut a = FF::new(9);
    // You can get the inner value by `inner` function
    let a_in = a.inner();
    assert_eq!(a_in, 9);
    // You can get the max value
    let mut b = FF::max();

    // you can get two special value `one` and `zero`
    let one = FF::one();
    let zero = FF::zero();

    // check `one` and `zero` by function
    assert!(one.is_one());
    assert!(zero.is_zero());

    // assign `one` and `zero` by function
    a.set_one();
    b.set_zero();

    // uniform random on all values of [`FF`]
    let mut a = FF::random();
    let b: FF = rand::random();
    let _a: FF = rng.gen();
    let _a: FF = Standard.sample(&mut rng);

    // custom uniform distribution
    let dis = rand::distributions::Uniform::new(FF(0), FF(64));
    let _a = dis.sample(&mut rng);

    // standard_distribution
    let _standard_distribution = FF::standard_distribution();
    // other distributions
    let _binary_distribution = FF::binary_distribution();
    let _ternary_distribution = FF::ternary_distribution();
    let _normal_distribution = FF::normal_distribution(0.0, 3.2)?;

    // Some operation
    let _c = a + b;
    let _c = a - b;
    let _c = a * b;
    let _c = a / b;
    let _c = a.double(); // a + a

    // Some assign operation
    a += b;
    a -= b;
    a *= b;
    a /= b;
    a.double_in_place(); // a += a;

    // neg operation
    a = -a;
    a.neg_in_place(); // a = -a;

    // inv operation
    a = a.inv(); // a = 1 / a;
    a = a.inverse().unwrap();
    a.inverse_in_place();

    // pow operation
    a = a.square(); // a = a * a
    a.square_in_place(); // a *= a
    a = a.pow(5);

    // you can print FF value by `Display` trait
    println!("a:{a}");

    // you can check whether the modulus is a prime number
    FF::is_prime_field();

    // through NTT, you can comput polynomial multiplication
    type PolyFF = Polynomial<FF>;
    const N: usize = 8;
    let a = PolyFF::new(
        FF::standard_distribution()
            .sample_iter(&mut rng)
            .take(N)
            .collect(),
    );
    let b = PolyFF::new(
        FF::standard_distribution()
            .sample_iter(&mut rng)
            .take(N)
            .collect(),
    );

    let _c = a * b;

    Ok(())
}
