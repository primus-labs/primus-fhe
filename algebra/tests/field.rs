use algebra::{decompose::NonPowOf2ApproxSignedBasis, reduce::ReduceExp, Field, U32FieldEval};
use rand::{distributions::Uniform, thread_rng, Rng};

type FF = U32FieldEval<132120577>;
type ValueT = u32;
type WideT = u64;

#[test]
fn test_fp() {
    let modulus = FF::MODULUS;
    let p = FF::MODULUS_VALUE;

    let distr = Uniform::new(0, p);
    let mut rng = thread_rng();

    // add
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = (a + b) % p;
    assert_eq!(FF::add(a, b), c);

    // add_assign
    let mut a = a;
    FF::add_assign(&mut a, b);
    assert_eq!(a, c);

    // sub
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = (p + a - b) % p;
    assert_eq!(FF::sub(a, b), c);

    // sub_assign
    let mut a = a;
    FF::sub_assign(&mut a, b);
    assert_eq!(a, c);

    // mul
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = ((a as WideT * b as WideT) % p as WideT) as ValueT;
    assert_eq!(FF::mul(a, b), c);

    // mul_assign
    let mut a = a;
    FF::mul_assign(&mut a, b);
    assert_eq!(a, c);

    // div
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let b_inv = modulus.reduce_exp(b, p - 2);
    let c = ((a as WideT * b_inv as WideT) % p as WideT) as ValueT;
    assert_eq!(FF::div(a, b), c);

    // div_assign
    let mut a = a;
    FF::div_assign(&mut a, b);
    assert_eq!(a, c);

    // neg
    let a = rng.sample(distr);
    let a_neg = FF::neg(a);
    assert_eq!(FF::add(a, a_neg), FF::ZERO);

    let a = FF::ZERO;
    assert_eq!(a, FF::neg(a));

    // inv
    let a = rng.sample(distr);
    let a_inv = modulus.reduce_exp(a, p - 2);
    assert_eq!(FF::inv(a), a_inv);
    assert_eq!(FF::mul(a, a_inv), FF::ONE);

    // associative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(FF::add(FF::add(a, b), c), FF::add(a, FF::add(b, c)),);
    assert_eq!(FF::mul(FF::mul(a, b), c), FF::mul(a, FF::mul(b, c)),);

    // commutative
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    assert_eq!(FF::add(a, b), FF::add(b, a));
    assert_eq!(FF::mul(a, b), FF::mul(b, a));

    // identity
    let a = rng.sample(distr);
    assert_eq!(FF::add(a, 0), a);
    assert_eq!(FF::mul(a, 1), a);

    // distribute
    let a = rng.sample(distr);
    let b = rng.sample(distr);
    let c = rng.sample(distr);
    assert_eq!(
        FF::mul(FF::add(a, b), c),
        FF::add(FF::mul(a, c), FF::mul(b, c))
    );
}

#[test]
fn test_decompose() {
    const BITS: u32 = 2;
    let rng = &mut thread_rng();
    let basis = <NonPowOf2ApproxSignedBasis<ValueT>>::new(FF::MODULUS_VALUE, BITS, Some(10));

    let a = rng.gen_range(0..=FF::MINUS_ONE);

    // decompose
    let (a_d, mut carry) = basis.init_value_carry(a);
    let decompose: Vec<ValueT> = basis
        .decompose_iter()
        .map(|once_decompose| {
            let (d, c) = once_decompose.decompose(a_d, carry);
            carry = c;
            d
        })
        .collect();

    // compose
    let compose = decompose
        .into_iter()
        .zip(basis.scalar_iter())
        .fold(0, |acc, (decomposed, scalar)| {
            FF::mul_add(decomposed, scalar, acc)
        });

    match basis.init_carry_mask() {
        Some(mask) => assert!(FF::sub(a, compose).min(FF::sub(compose, a)) <= mask),
        None => assert_eq!(compose, a),
    };
}
