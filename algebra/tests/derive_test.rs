use algebra::derive::{Field, Prime, NTT};

#[derive(Field, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

#[cfg(test)]
mod tests {
    use super::*;

    use algebra::{
        modulus::{
            from_monty, to_canonical_u64, to_monty, BabyBearModulus, BarrettModulus,
            GoldilocksModulus,
        },
        reduce::*,
        BabyBear, Basis, Field, FieldUniformSampler, Goldilocks, ModulusConfig, PrimeField,
    };
    use num_traits::{Inv, One, Zero};
    use rand::{distributions::Uniform, thread_rng, Rng};
    use rand_distr::Distribution;

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
        assert_eq!(FF::lazy_new(a) + FF::lazy_new(b), FF::lazy_new(c));

        // add_assign
        let mut a = FF::lazy_new(a);
        a += FF::lazy_new(b);
        assert_eq!(a, FF::lazy_new(c));

        // sub
        let a = rng.sample(distr);
        let b = rng.gen_range(0..=a);
        let c = (a - b) % p;
        assert_eq!(FF::lazy_new(a) - FF::lazy_new(b), FF::lazy_new(c));

        // sub_assign
        let mut a = FF::lazy_new(a);
        a -= FF::lazy_new(b);
        assert_eq!(a, FF::lazy_new(c));

        // mul
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = ((a as W * b as W) % p as W) as T;
        assert_eq!(FF::lazy_new(a) * FF::lazy_new(b), FF::lazy_new(c));

        // mul_assign
        let mut a = FF::lazy_new(a);
        a *= FF::lazy_new(b);
        assert_eq!(a, FF::lazy_new(c));

        // div
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let b_inv = b.pow_reduce(p - 2, BarrettModulus::<T>::new(p));
        let c = ((a as W * b_inv as W) % p as W) as T;
        assert_eq!(FF::lazy_new(a) / FF::lazy_new(b), FF::lazy_new(c));

        // div_assign
        let mut a = FF::lazy_new(a);
        a /= FF::lazy_new(b);
        assert_eq!(a, FF::lazy_new(c));

        // neg
        let a = rng.sample(distr);
        let a_neg = -FF::lazy_new(a);
        assert_eq!(FF::lazy_new(a) + a_neg, FF::zero());

        let a = FF::zero();
        assert_eq!(a, -a);

        // inv
        let a = rng.sample(distr);
        let a_inv = a.pow_reduce(p - 2, BarrettModulus::<T>::new(p));
        assert_eq!(FF::lazy_new(a).inv(), FF::lazy_new(a_inv));
        assert_eq!(FF::lazy_new(a) * FF::lazy_new(a_inv), FF::one());

        // associative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (FF::lazy_new(a) + FF::lazy_new(b)) + FF::lazy_new(c),
            FF::lazy_new(a) + (FF::lazy_new(b) + FF::lazy_new(c))
        );
        assert_eq!(
            (FF::lazy_new(a) * FF::lazy_new(b)) * FF::lazy_new(c),
            FF::lazy_new(a) * (FF::lazy_new(b) * FF::lazy_new(c))
        );

        // commutative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        assert_eq!(
            FF::lazy_new(a) + FF::lazy_new(b),
            FF::lazy_new(b) + FF::lazy_new(a)
        );
        assert_eq!(
            FF::lazy_new(a) * FF::lazy_new(b),
            FF::lazy_new(b) * FF::lazy_new(a)
        );

        // identity
        let a = rng.sample(distr);
        assert_eq!(FF::lazy_new(a) + FF::lazy_new(0), FF::lazy_new(a));
        assert_eq!(FF::lazy_new(a) * FF::lazy_new(1), FF::lazy_new(a));

        // distribute
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (FF::lazy_new(a) + FF::lazy_new(b)) * FF::lazy_new(c),
            (FF::lazy_new(a) * FF::lazy_new(c)) + (FF::lazy_new(b) * FF::lazy_new(c))
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
            .fold(FF::lazy_new(0), |acc, (i, d)| {
                acc + d * FF::new(B.pow(i as T) as T)
            });

        assert_eq!(compose, a);
    }

    #[test]
    fn baby_bear_test() {
        let p = BabyBear::MODULUS_VALUE;

        let distr = Uniform::new(0, p);
        let mut rng = thread_rng();

        assert!(BabyBear::is_prime_field());

        // add
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = (a + b) % p;
        assert_eq!(
            BabyBear::lazy_new(a) + BabyBear::lazy_new(b),
            BabyBear::lazy_new(c)
        );

        // add_assign
        let mut a = BabyBear::lazy_new(a);
        a += BabyBear::lazy_new(b);
        assert_eq!(a, BabyBear::lazy_new(c));

        // sub
        let a = rng.sample(distr);
        let b = rng.gen_range(0..=a);
        let c = (a - b) % p;
        assert_eq!(
            BabyBear::lazy_new(a) - BabyBear::lazy_new(b),
            BabyBear::lazy_new(c)
        );

        // sub_assign
        let mut a = BabyBear::lazy_new(a);
        a -= BabyBear::lazy_new(b);
        assert_eq!(a, BabyBear::lazy_new(c));

        // mul
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = ((a as W * b as W) % p as W) as T;
        assert_eq!(
            BabyBear::lazy_new(a) * BabyBear::lazy_new(b),
            BabyBear::lazy_new(c)
        );

        // mul_assign
        let mut a = BabyBear::lazy_new(a);
        a *= BabyBear::lazy_new(b);
        assert_eq!(a, BabyBear::lazy_new(c));

        // div
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let b_inv = from_monty((to_monty(b)).pow_reduce(p - 2, BabyBearModulus));
        let c = ((a as W * b_inv as W) % (p as W)) as T;
        assert_eq!(
            BabyBear::lazy_new(a) / BabyBear::lazy_new(b),
            BabyBear::lazy_new(c)
        );

        // div_assign
        let mut a = BabyBear::lazy_new(a);
        a /= BabyBear::lazy_new(b);
        assert_eq!(a, BabyBear::lazy_new(c));

        // neg
        let a = rng.sample(distr);
        let a_neg = -BabyBear::lazy_new(a);
        assert_eq!(BabyBear::lazy_new(a) + a_neg, BabyBear::zero());

        let a = BabyBear::zero();
        assert_eq!(a, -a);

        // inv
        let a = rng.sample(distr);
        let a_inv = from_monty((to_monty(a)).pow_reduce(p - 2, BabyBearModulus));
        assert_eq!(BabyBear::lazy_new(a).inv(), BabyBear::lazy_new(a_inv));
        assert_eq!(
            BabyBear::lazy_new(a) * BabyBear::lazy_new(a_inv),
            BabyBear::one()
        );

        // associative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (BabyBear::lazy_new(a) + BabyBear::lazy_new(b)) + BabyBear::lazy_new(c),
            BabyBear::lazy_new(a) + (BabyBear::lazy_new(b) + BabyBear::lazy_new(c))
        );
        assert_eq!(
            (BabyBear::lazy_new(a) * BabyBear::lazy_new(b)) * BabyBear::lazy_new(c),
            BabyBear::lazy_new(a) * (BabyBear::lazy_new(b) * BabyBear::lazy_new(c))
        );

        // commutative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        assert_eq!(
            BabyBear::lazy_new(a) + BabyBear::lazy_new(b),
            BabyBear::lazy_new(b) + BabyBear::lazy_new(a)
        );
        assert_eq!(
            BabyBear::lazy_new(a) * BabyBear::lazy_new(b),
            BabyBear::lazy_new(b) * BabyBear::lazy_new(a)
        );

        // identity
        let a = rng.sample(distr);
        assert_eq!(
            BabyBear::lazy_new(a) + BabyBear::lazy_new(0),
            BabyBear::lazy_new(a)
        );
        assert_eq!(
            BabyBear::lazy_new(a) * BabyBear::lazy_new(1),
            BabyBear::lazy_new(a)
        );

        // distribute
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (BabyBear::lazy_new(a) + BabyBear::lazy_new(b)) * BabyBear::lazy_new(c),
            (BabyBear::lazy_new(a) * BabyBear::lazy_new(c))
                + (BabyBear::lazy_new(b) * BabyBear::lazy_new(c))
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
            .fold(BabyBear::lazy_new(0), |acc, (i, d)| {
                acc + d * BabyBear::new(B.pow(i as T) as T)
            });

        assert_eq!(compose, a);
    }

    #[test]
    fn goldilocks_test() {
        let p = Goldilocks::MODULUS_VALUE;

        let distr = Uniform::new(0, p);
        let mut rng = thread_rng();

        assert!(Goldilocks::is_prime_field());

        // add
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = ((a as u128 + b as u128) % (p as u128)) as u64;
        assert_eq!(
            Goldilocks::lazy_new(a) + Goldilocks::lazy_new(b),
            Goldilocks::lazy_new(c)
        );

        // add_assign
        let mut a = Goldilocks::lazy_new(a);
        a += Goldilocks::lazy_new(b);
        assert_eq!(a, Goldilocks::lazy_new(c));

        // sub
        let a = rng.sample(distr);
        let b = rng.gen_range(0..=a);
        let c = (a - b) % p;
        assert_eq!(
            Goldilocks::lazy_new(a) - Goldilocks::lazy_new(b),
            Goldilocks::lazy_new(c)
        );

        // sub_assign
        let mut a = Goldilocks::lazy_new(a);
        a -= Goldilocks::lazy_new(b);
        assert_eq!(a, Goldilocks::lazy_new(c));

        // mul
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = ((a as u128 * b as u128) % p as u128) as u64;
        assert_eq!(
            Goldilocks::lazy_new(a) * Goldilocks::lazy_new(b),
            Goldilocks::lazy_new(c)
        );

        // mul_assign
        let mut a = Goldilocks::lazy_new(a);
        a *= Goldilocks::lazy_new(b);
        assert_eq!(a, Goldilocks::lazy_new(c));

        // div
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let b_inv = to_canonical_u64(b.pow_reduce(p - 2, GoldilocksModulus));
        let c = ((a as u128 * b_inv as u128) % (p as u128)) as u64;
        assert_eq!(
            Goldilocks::lazy_new(a) / Goldilocks::lazy_new(b),
            Goldilocks::lazy_new(c)
        );

        // div_assign
        let mut a = Goldilocks::lazy_new(a);
        a /= Goldilocks::lazy_new(b);
        assert_eq!(a, Goldilocks::lazy_new(c));

        // neg
        let a = rng.sample(distr);
        let a_neg = -Goldilocks::lazy_new(a);
        assert_eq!(Goldilocks::lazy_new(a) + a_neg, Goldilocks::zero());

        let a = Goldilocks::zero();
        assert_eq!(a, -a);

        // inv
        let a = rng.sample(distr);
        let a_inv = to_canonical_u64(a.pow_reduce(p - 2, GoldilocksModulus));
        assert_eq!(Goldilocks::lazy_new(a).inv(), Goldilocks::lazy_new(a_inv));
        assert_eq!(
            Goldilocks::lazy_new(a) * Goldilocks::lazy_new(a_inv),
            Goldilocks::one()
        );

        // associative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (Goldilocks::lazy_new(a) + Goldilocks::lazy_new(b)) + Goldilocks::lazy_new(c),
            Goldilocks::lazy_new(a) + (Goldilocks::lazy_new(b) + Goldilocks::lazy_new(c))
        );
        assert_eq!(
            (Goldilocks::lazy_new(a) * Goldilocks::lazy_new(b)) * Goldilocks::lazy_new(c),
            Goldilocks::lazy_new(a) * (Goldilocks::lazy_new(b) * Goldilocks::lazy_new(c))
        );

        // commutative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        assert_eq!(
            Goldilocks::lazy_new(a) + Goldilocks::lazy_new(b),
            Goldilocks::lazy_new(b) + Goldilocks::lazy_new(a)
        );
        assert_eq!(
            Goldilocks::lazy_new(a) * Goldilocks::lazy_new(b),
            Goldilocks::lazy_new(b) * Goldilocks::lazy_new(a)
        );

        // identity
        let a = rng.sample(distr);
        assert_eq!(
            Goldilocks::lazy_new(a) + Goldilocks::lazy_new(0),
            Goldilocks::lazy_new(a)
        );
        assert_eq!(
            Goldilocks::lazy_new(a) * Goldilocks::lazy_new(1),
            Goldilocks::lazy_new(a)
        );

        // distribute
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (Goldilocks::lazy_new(a) + Goldilocks::lazy_new(b)) * Goldilocks::lazy_new(c),
            (Goldilocks::lazy_new(a) * Goldilocks::lazy_new(c))
                + (Goldilocks::lazy_new(b) * Goldilocks::lazy_new(c))
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
            .fold(Goldilocks::lazy_new(0), |acc, (i, d)| {
                acc + d * Goldilocks::new((B as u64).pow(i as u32))
            });

        assert_eq!(compose, a);
    }
}
