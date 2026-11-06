/// Tests primality deterministically over the complete `u64` range.
///
/// Uses the seven Miller–Rabin bases for `n < 2^64`, with exact `u128`
/// modular products. This is cold parameter preparation, not a constant-time
/// operation for secret inputs. A prime result alone establishes neither NTT
/// compatibility nor a cryptographic security level.
///
/// The same bases are used by [SymPy's deterministic branch](https://github.com/sympy/sympy/blob/master/sympy/ntheory/primetest.py).
#[must_use]
pub fn is_prime_u64(n: u64) -> bool {
    if n < 2 || n.is_multiple_of(2) {
        return n == 2;
    }
    let powers = (n - 1).trailing_zeros();
    let odd = (n - 1) >> powers;
    for base in [2u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        let mut base = base % n;
        if base == 0 {
            continue;
        }
        let mut exponent = odd;
        let mut value = 1u64;
        while exponent != 0 {
            if exponent & 1 != 0 {
                value = (value as u128 * base as u128 % n as u128) as u64;
            }
            base = (base as u128 * base as u128 % n as u128) as u64;
            exponent >>= 1;
        }
        if value == 1 || value == n - 1 {
            continue;
        }
        let mut passed = false;
        for _ in 1..powers {
            value = (value as u128 * value as u128 % n as u128) as u64;
            if value == n - 1 {
                passed = true;
                break;
            }
        }
        if !passed {
            return false;
        }
    }
    true
}
