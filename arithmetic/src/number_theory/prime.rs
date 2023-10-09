use rand::{distributions::Uniform, prelude::Distribution, rngs::StdRng, thread_rng, SeedableRng};

use crate::{modulo::{Modulus, PowerModulo, Modulo}, primitive::BigIntHelperMethods};

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

/// Check whether the `modulus`'s value is a prime number through Miller-Rabin primality test algorithm.
///
/// This is a probabilistic algorithm. Its error-probability bound is `(1/4)^rounds`.
///
/// See Handbook of Applied Cryptography, p. 139, Algorithm 4.24.
pub fn probably_prime(modulus: &Modulus, rounds: usize) -> bool {
    let value: u64 = modulus.value();

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

    let value_sub_one: u64 = value - 1;
    let r: u64 = value_sub_one.trailing_zeros() as u64;
    let q = value_sub_one >> r;

    let distribution: Uniform<u64> = Uniform::from(3..=value_sub_one);
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();

    'next_round: for i in 0..rounds {
        let a: u64 = if i != 0 {
            distribution.sample(&mut rng)
        } else {
            2
        };
        let mut x: u64 = a.pow_modulo(q, modulus);
        if x == 1 || x == value_sub_one {
            continue;
        }

        for _ in 1..r {
            x = x.widen_mul(x).modulo(modulus);
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
