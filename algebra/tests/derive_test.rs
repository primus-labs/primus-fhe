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

#[cfg(feature = "concrete-ntt")]
use algebra::{
    modulus::{from_monty, to_canonical_u64, to_monty, BabyBearModulus, GoldilocksModulus},
    BabyBear, Goldilocks,
};

#[test]
#[cfg(feature = "concrete-ntt")]
fn baby_bear_test() {
    let p = BabyBear::MODULUS_VALUE;

    let distr = Uniform::new(0, p);
    let mut rng = thread_rng();

    assert!(BabyBear::is_prime_field());

    // add
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = (a + b) % p;
    assert_eq!(BabyBear::new(a) + BabyBear::new(b), BabyBear::new(c));

    // add_assign
    let mut a = BabyBear::new(a);
    a += BabyBear::new(b);
    assert_eq!(a, BabyBear::new(c));

    // sub
    let a = rng.sample(distr);
    let b = rng.gen_range(0..=a);
    let c = (a - b) % p;
    assert_eq!(BabyBear::new(a) - BabyBear::new(b), BabyBear::new(c));

    // sub_assign
    let mut a = BabyBear::new(a);
    a -= BabyBear::new(b);
    assert_eq!(a, BabyBear::new(c));

    // mul
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = ((a as W * b as W) % p as W) as T;
    assert_eq!(BabyBear::new(a) * BabyBear::new(b), BabyBear::new(c));

    // mul_assign
    let mut a = BabyBear::new(a);
    a *= BabyBear::new(b);
    assert_eq!(a, BabyBear::new(c));

    // div
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let b_inv = from_monty((to_monty(b)).exp_reduce(p - 2, BabyBearModulus));
    let c = ((a as W * b_inv as W) % (p as W)) as T;
    assert_eq!(BabyBear::new(a) / BabyBear::new(b), BabyBear::new(c));

    // div_assign
    let mut a = BabyBear::new(a);
    a /= BabyBear::new(b);
    assert_eq!(a, BabyBear::new(c));

    // neg
    let a = rng.sample(distr);
    let a_neg = -BabyBear::new(a);
    assert_eq!(BabyBear::new(a) + a_neg, BabyBear::zero());

    let a = BabyBear::zero();
    assert_eq!(a, -a);

    // inv
    let a = rng.sample(distr);
    let a_inv = from_monty((to_monty(a)).exp_reduce(p - 2, BabyBearModulus));
    assert_eq!(BabyBear::new(a).inv(), BabyBear::new(a_inv));
    assert_eq!(BabyBear::new(a) * BabyBear::new(a_inv), BabyBear::one());

    // associative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(
        (BabyBear::new(a) + BabyBear::new(b)) + BabyBear::new(c),
        BabyBear::new(a) + (BabyBear::new(b) + BabyBear::new(c))
    );
    assert_eq!(
        (BabyBear::new(a) * BabyBear::new(b)) * BabyBear::new(c),
        BabyBear::new(a) * (BabyBear::new(b) * BabyBear::new(c))
    );

    // commutative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    assert_eq!(
        BabyBear::new(a) + BabyBear::new(b),
        BabyBear::new(b) + BabyBear::new(a)
    );
    assert_eq!(
        BabyBear::new(a) * BabyBear::new(b),
        BabyBear::new(b) * BabyBear::new(a)
    );

    // identity
    let a = rng.sample(distr);
    assert_eq!(BabyBear::new(a) + BabyBear::new(0), BabyBear::new(a));
    assert_eq!(BabyBear::new(a) * BabyBear::new(1), BabyBear::new(a));

    // distribute
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(
        (BabyBear::new(a) + BabyBear::new(b)) * BabyBear::new(c),
        (BabyBear::new(a) * BabyBear::new(c)) + (BabyBear::new(b) * BabyBear::new(c))
    );

    const BITS: u32 = 2;
    const B: u32 = 1 << BITS;
    let basis = <Basis<BabyBear>>::new(BITS);
    let rng = &mut thread_rng();

    let uniform = <FieldUniformSampler<BabyBear>>::new();
    let a: BabyBear = uniform.sample(rng);
    let decompose = a.decompose(basis);
    let compose = decompose
        .into_iter()
        .enumerate()
        .fold(BabyBear::new(0), |acc, (i, d)| {
            acc + d * BabyBear::new(B.pow(i as T) as T)
        });

    assert_eq!(compose, a);
}

#[test]
#[cfg(feature = "concrete-ntt")]
fn goldilocks_test() {
    let p = Goldilocks::MODULUS_VALUE;

    let distr = Uniform::new(0, p);
    let mut rng = thread_rng();

    assert!(Goldilocks::is_prime_field());

    // add
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = ((a as u128 + b as u128) % (p as u128)) as u64;
    assert_eq!(Goldilocks::new(a) + Goldilocks::new(b), Goldilocks::new(c));

    // add_assign
    let mut a = Goldilocks::new(a);
    a += Goldilocks::new(b);
    assert_eq!(a, Goldilocks::new(c));

    // sub
    let a = rng.sample(distr);
    let b = rng.gen_range(0..=a);
    let c = (a - b) % p;
    assert_eq!(Goldilocks::new(a) - Goldilocks::new(b), Goldilocks::new(c));

    // sub_assign
    let mut a = Goldilocks::new(a);
    a -= Goldilocks::new(b);
    assert_eq!(a, Goldilocks::new(c));

    // mul
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = ((a as u128 * b as u128) % p as u128) as u64;
    assert_eq!(Goldilocks::new(a) * Goldilocks::new(b), Goldilocks::new(c));

    // mul_assign
    let mut a = Goldilocks::new(a);
    a *= Goldilocks::new(b);
    assert_eq!(a, Goldilocks::new(c));

    // div
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let b_inv = to_canonical_u64(b.exp_reduce(p - 2, GoldilocksModulus));
    let c = ((a as u128 * b_inv as u128) % (p as u128)) as u64;
    assert_eq!(Goldilocks::new(a) / Goldilocks::new(b), Goldilocks::new(c));

    // div_assign
    let mut a = Goldilocks::new(a);
    a /= Goldilocks::new(b);
    assert_eq!(a, Goldilocks::new(c));

    // neg
    let a = rng.sample(distr);
    let a_neg = -Goldilocks::new(a);
    assert_eq!(Goldilocks::new(a) + a_neg, Goldilocks::zero());

    let a = Goldilocks::zero();
    assert_eq!(a, -a);

    // inv
    let a = rng.sample(distr);
    let a_inv = to_canonical_u64(a.exp_reduce(p - 2, GoldilocksModulus));
    assert_eq!(Goldilocks::new(a).inv(), Goldilocks::new(a_inv));
    assert_eq!(
        Goldilocks::new(a) * Goldilocks::new(a_inv),
        Goldilocks::one()
    );

    // associative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(
        (Goldilocks::new(a) + Goldilocks::new(b)) + Goldilocks::new(c),
        Goldilocks::new(a) + (Goldilocks::new(b) + Goldilocks::new(c))
    );
    assert_eq!(
        (Goldilocks::new(a) * Goldilocks::new(b)) * Goldilocks::new(c),
        Goldilocks::new(a) * (Goldilocks::new(b) * Goldilocks::new(c))
    );

    // commutative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    assert_eq!(
        Goldilocks::new(a) + Goldilocks::new(b),
        Goldilocks::new(b) + Goldilocks::new(a)
    );
    assert_eq!(
        Goldilocks::new(a) * Goldilocks::new(b),
        Goldilocks::new(b) * Goldilocks::new(a)
    );

    // identity
    let a = rng.sample(distr);
    assert_eq!(Goldilocks::new(a) + Goldilocks::new(0), Goldilocks::new(a));
    assert_eq!(Goldilocks::new(a) * Goldilocks::new(1), Goldilocks::new(a));

    // distribute
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(
        (Goldilocks::new(a) + Goldilocks::new(b)) * Goldilocks::new(c),
        (Goldilocks::new(a) * Goldilocks::new(c)) + (Goldilocks::new(b) * Goldilocks::new(c))
    );

    const BITS: u32 = 2;
    const B: u32 = 1 << BITS;
    let basis = <Basis<Goldilocks>>::new(BITS);
    let rng = &mut thread_rng();

    let uniform = <FieldUniformSampler<Goldilocks>>::new();
    let a: Goldilocks = uniform.sample(rng);
    let decompose = a.decompose(basis);
    let compose = decompose
        .into_iter()
        .enumerate()
        .fold(Goldilocks::new(0), |acc, (i, d)| {
            acc + d * Goldilocks::new((B as u64).pow(i as u32))
        });

    assert_eq!(compose, a);
}
