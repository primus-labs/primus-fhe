use rand::{distributions::Uniform, prelude::Distribution, rngs::StdRng, thread_rng, SeedableRng};

use crate::modulus::BarrettModulus;
use crate::reduce::{ExpReduce, Reduce};

/// The trait defines some function for prime number
pub trait Prime {
    /// Check whether the `modulus`'s value is a prime number through Miller-Rabin primality test algorithm.
    ///
    /// This is a probabilistic algorithm. Its error-probability bound is `(1/4)^rounds`.
    ///
    /// See Handbook of Applied Cryptography, p. 139, Algorithm 4.24.
    fn probably_prime(self, rounds: usize) -> bool;
}

macro_rules! impl_prime_check {
    (impl Prime for BarrettModulus<$SelfT:ty>) => {
        impl Prime for BarrettModulus<$SelfT> {
            fn probably_prime(self, rounds: usize) -> bool {
                /// Records the primes < 64.
                const PRIME_BIT_MASK: u64 = 1 << 2
                    | 1 << 3
                    | 1 << 5
                    | 1 << 7
                    | 1 << 11
                    | 1 << 13
                    | 1 << 17
                    | 1 << 19
                    | 1 << 23
                    | 1 << 29
                    | 1 << 31
                    | 1 << 37
                    | 1 << 41
                    | 1 << 43
                    | 1 << 47
                    | 1 << 53
                    | 1 << 59
                    | 1 << 61;

                let value: $SelfT = self.value();

                if value == 0 {
                    return false;
                }

                if value < 64 {
                    return (PRIME_BIT_MASK & (1 << value)) != 0;
                }

                // even
                if 0 == (value & 0x1) {
                    return false;
                }

                if (value % 3) == 0
                    || (value % 5) == 0
                    || (value % 7) == 0
                    || (value % 11) == 0
                    || (value % 13) == 0
                    || (value % 17) == 0
                    || (value % 19) == 0
                    || (value % 23) == 0
                    || (value % 29) == 0
                    || (value % 31) == 0
                    || (value % 37) == 0
                    || (value % 41) == 0
                    || (value % 43) == 0
                    || (value % 47) == 0
                    || (value % 53) == 0
                {
                    return false;
                }

                let value_sub_one: $SelfT = value - 1;
                let r: $SelfT = value_sub_one.trailing_zeros() as $SelfT;
                let q = value_sub_one >> r;

                let distribution: Uniform<$SelfT> = Uniform::from(3..=value_sub_one);
                let mut rng = StdRng::from_rng(thread_rng()).unwrap();

                'next_round: for i in 0..rounds {
                    let a: $SelfT = if i != 0 {
                        distribution.sample(&mut rng)
                    } else {
                        2
                    };
                    let mut x: $SelfT = a.exp_reduce(q, self);
                    if x == 1 || x == value_sub_one {
                        continue;
                    }

                    for _ in 1..r {
                        x = $crate::WideningMul::widening_mul(x, x).reduce(self);
                        if x == value_sub_one {
                            break 'next_round;
                        }
                        if x == 1 {
                            return false;
                        }
                    }
                    return false;
                }
                true
            }
        }
    };
}

impl_prime_check!(impl Prime for BarrettModulus<u64>);

impl_prime_check!(impl Prime for BarrettModulus<u32>);

impl_prime_check!(impl Prime for BarrettModulus<u16>);

impl_prime_check!(impl Prime for BarrettModulus<u8>);

#[cfg(test)]
mod tests {
    use rand::prelude::*;

    use super::*;

    fn simple_prime_test(modulus: u64) -> bool {
        let root = (modulus as f64).sqrt().ceil() as u64;

        if modulus.rem_euclid(2) == 0 {
            return false;
        }
        for r in (3..=root).step_by(2) {
            if modulus.rem_euclid(r) == 0 {
                return false;
            }
        }
        true
    }

    #[test]
    fn test_prime_test() {
        let mut r = thread_rng();

        for _ in 0..5 {
            let m = r.gen_range(2..=(u64::MAX >> 2));
            let modulus = BarrettModulus::<u64>::new(m);
            let is_prime = modulus.probably_prime(20);
            assert_eq!(is_prime, simple_prime_test(m));
        }
    }
}
