use algebra::derive::{Field, Prime, Random, Ring, NTT};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Random)]
#[modulus = 512]
pub struct R512(u32);

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
)]
#[modulus = 132120577]
pub struct Fp32(u32);

#[cfg(test)]
mod tests {
    use super::*;

    use algebra::field::BarrettConfig;
    use algebra::field::NTTField;
    use algebra::field::PrimeField;
    use algebra::modulo_traits::*;
    use algebra::modulus::Modulus;
    use algebra::ring::Ring;
    use num_traits::Inv;
    use rand::distributions::Uniform;
    use rand::thread_rng;
    use rand::Rng;

    type FF = Fp32;
    type RR = R512;
    type T = u32;
    type W = u64;

    #[test]
    fn test_fp() {
        let p = FF::BARRETT_MODULUS.value();

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
        let b_inv = b.pow_reduce(p - 2, &Modulus::<T>::new(p));
        let c = ((a as W * b_inv as W) % p as W) as T;
        assert_eq!(FF::new(a) / FF::new(b), FF::new(c));

        // div_assign
        let mut a = FF::new(a);
        a /= FF::new(b);
        assert_eq!(a, FF::new(c));

        // neg
        let a = rng.sample(distr);
        let a_neg = -FF::new(a);
        assert_eq!(FF::new(a) + a_neg, num_traits::Zero::zero());

        // inv
        let a = rng.sample(distr);
        let a_inv = a.pow_reduce(p - 2, &Modulus::<T>::new(p));
        assert_eq!(FF::new(a).inv(), FF::new(a_inv));
        assert_eq!(FF::new(a) * FF::new(a_inv), num_traits::One::one());

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
        const B: u32 = 1 << 2;
        let rng = &mut thread_rng();

        let a: FF = rng.gen();
        let decompose = a.decompose(B);
        let compose = decompose
            .into_iter()
            .enumerate()
            .fold(FF::new(0), |acc, (i, d)| acc + d.mul_scalar(B.pow(i as T)));

        assert_eq!(compose, a);
    }

    #[test]
    fn test_ring() {
        let max = RR::max().0;
        let m = max + 1;

        let distr = Uniform::new_inclusive(0, max);
        let mut rng = thread_rng();

        // add
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = (a + b) % m;
        assert_eq!(RR::new(a) + RR::new(b), RR::new(c));

        // add_assign
        let mut a = RR::new(a);
        a += RR::new(b);
        assert_eq!(a, RR::new(c));

        // sub
        let a = rng.sample(distr);
        let b = rng.gen_range(0..=a);
        let c = (a - b) % m;
        assert_eq!(RR::new(a) - RR::new(b), RR::new(c));

        // sub_assign
        let mut a = RR::new(a);
        a -= RR::new(b);
        assert_eq!(a, RR::new(c));

        // mul
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = ((a as W * b as W) % m as W) as T;
        assert_eq!(RR::new(a) * RR::new(b), RR::new(c));

        // mul_assign
        let mut a = RR::new(a);
        a *= RR::new(b);
        assert_eq!(a, RR::new(c));

        // neg
        let a = rng.sample(distr);
        let a_neg = -RR::new(a);
        assert_eq!(RR::new(a) + a_neg, num_traits::Zero::zero());

        // associative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (RR::new(a) + RR::new(b)) + RR::new(c),
            RR::new(a) + (RR::new(b) + RR::new(c))
        );
        assert_eq!(
            (RR::new(a) * RR::new(b)) * RR::new(c),
            RR::new(a) * (RR::new(b) * RR::new(c))
        );

        // commutative
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        assert_eq!(RR::new(a) + RR::new(b), RR::new(b) + RR::new(a));
        assert_eq!(RR::new(a) * RR::new(b), RR::new(b) * RR::new(a));

        // identity
        let a = rng.sample(distr);
        assert_eq!(RR::new(a) + RR::new(0), RR::new(a));
        assert_eq!(RR::new(a) * RR::new(1), RR::new(a));

        // distribute
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = rng.sample(distr);
        assert_eq!(
            (RR::new(a) + RR::new(b)) * RR::new(c),
            (RR::new(a) * RR::new(c)) + (RR::new(b) * RR::new(c))
        );
    }
}
