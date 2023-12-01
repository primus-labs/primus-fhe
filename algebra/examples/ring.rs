use algebra::derive::{Random, Ring};
use algebra::field::FieldDistribution;
use algebra::ring::Ring;
use num_traits::{One, Pow, Zero};
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Random)]
#[modulus = 512]
pub struct RR(u32);

fn main() -> Result<(), algebra::AlgebraError> {
    let rng = &mut thread_rng();

    // You can generate a value by yourself
    let mut a = RR::new(9);
    // You can get the inner value by `inner` function
    let _a = a.inner();
    // You can get the max value
    let mut b = RR::max();

    // you can get two special value `one` and `zero`
    let one = RR::one();
    let zero = RR::zero();

    // check `one` and `zero` by function
    assert!(one.is_one());
    assert!(zero.is_zero());

    // assign `one` and `zero` by function
    a.set_one();
    b.set_zero();

    // uniform random on all values of [`RR`]
    let mut a = RR::random();
    let b: RR = rand::random();
    let _a: RR = rng.gen();
    let _a: RR = Standard.sample(rng);

    // custom uniform distribution
    let dis = rand::distributions::Uniform::new(RR(0), RR(64));
    let _a = dis.sample(rng);

    // standard_distribution
    let _standard_distribution = RR::standard_distribution();
    // other distributions
    let _binary_distribution = RR::binary_distribution();
    let _ternary_distribution = RR::ternary_distribution();
    let _normal_distribution = RR::normal_distribution(0.0, 3.2)?;

    // Some operation
    let _c = a + b;
    let _c = a - b;
    let _c = a * b;
    let _c = a.double(); // a + a

    // Some assign operation
    a += b;
    a -= b;
    a *= b;
    a.double_in_place(); // a += a

    // neg operation
    a = -a;
    a.neg_in_place(); // a = -a;

    // pow operation
    a = a.square(); // a = a * a
    a.square_in_place(); // a *= a
    a = a.pow(5);

    // you can print RR value by `Display` trait
    println!("a:{a}");

    Ok(())
}
