use algebra_derive::{AlgebraRandom, Field, NTTField, Prime, Ring};

/// A finite Field type, whose inner size is 32bits.
///
/// Now, it's focused on the prime field.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Ring,
    Field,
    AlgebraRandom,
    Prime,
    NTTField,
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
    use rand::thread_rng;
    use rand::Rng;

    #[test]
    fn test_fp() {
        const P: u32 = Fp32::BARRETT_MODULUS.value();

        let distr = rand::distributions::Uniform::new(0, P);
        let mut rng = thread_rng();

        type FF = Fp32;
        assert!(FF::is_prime_field());

        // add
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = (a + b) % P;
        assert_eq!(FF::new(a) + FF::new(b), FF::new(c));

        // add_assign
        let mut a = FF::new(a);
        a += FF::new(b);
        assert_eq!(a, FF::new(c));

        // sub
        let a = rng.sample(distr);
        let b = rng.gen_range(0..=a);
        let c = (a - b) % P;
        assert_eq!(FF::new(a) - FF::new(b), FF::new(c));

        // sub_assign
        let mut a = FF::new(a);
        a -= FF::new(b);
        assert_eq!(a, FF::new(c));

        // mul
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let c = ((a as u64 * b as u64) % P as u64) as u32;
        assert_eq!(FF::new(a) * FF::new(b), FF::new(c));

        // mul_assign
        let mut a = FF::new(a);
        a *= FF::new(b);
        assert_eq!(a, FF::new(c));

        // div
        let a = rng.sample(distr);
        let b = rng.sample(distr);
        let b_inv = b.pow_reduce(P - 2, &Modulus::<u32>::new(P));
        let c = ((a as u64 * b_inv as u64) % P as u64) as u32;
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
        let a_inv = a.pow_reduce(P - 2, &Modulus::<u32>::new(P));
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

        let a: Fp32 = rng.gen();
        let decompose = a.decompose(B);
        let compose = decompose
            .into_iter()
            .enumerate()
            .fold(Fp32(0), |acc, (i, d)| acc + d.mul_scalar(B.pow(i as u32)));

        assert_eq!(compose, a);
    }
}
