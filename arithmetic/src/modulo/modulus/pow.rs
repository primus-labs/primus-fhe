use crate::modulo::{MulModulo, PowerModulo};

use super::Modulus;

impl PowerModulo<Modulus> for u64 {
    type Exponent = Self;

    fn pow_modulo(self, mut exponent: Self::Exponent, modulus: &Modulus) -> Self {
        if exponent == 0 {
            return 1;
        }

        debug_assert!(self < modulus.value());

        if exponent == 1 {
            return self;
        }

        let mut power: u64 = self;
        let mut intermediate: u64 = 1;
        loop {
            if (exponent & 1) != 0 {
                intermediate = intermediate.mul_modulo(power, modulus);
            }
            exponent >>= 1;
            if exponent == 0 {
                break;
            }
            power = power.mul_modulo(power, modulus);
        }
        intermediate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_mod_simple() {
        let base: u64 = 12;
        let exp = 8;
        let m = 15;
        let modulus = Modulus::new(m);
        assert_eq!(base.pow(exp) % m, base.pow_modulo(exp as u64, &modulus));
    }
}
