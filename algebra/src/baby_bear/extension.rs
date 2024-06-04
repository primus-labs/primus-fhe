use crate::{
    extension::TwoAdicField, field::Field, modulus::to_monty, BabyBear, BinomialExtensionField,
    BinomiallyExtendable, HasTwoAdicBionmialExtension,
};
use num_traits::{One, Zero};

impl BinomiallyExtendable<4> for BabyBear {
    // Verifiable in Sage with
    // `R.<x> = GF(p)[]; assert (x^4 - 11).is_irreducible()`.
    fn w() -> Self {
        Self::new(11)
    }

    // DTH_ROOT = W^((p - 1)/4)
    fn dth_root() -> Self {
        Self::new(1728404513)
    }

    fn ext_generator() -> [Self; 4] {
        [Self::new(8), Self::one(), Self::zero(), Self::zero()]
    }
}

impl HasTwoAdicBionmialExtension<4> for BabyBear {
    const EXT_TWO_ADICITY: usize = 29;

    fn ext_two_adic_generator(bits: usize) -> [Self; 4] {
        assert!(bits <= 29);

        match bits {
            29 => [
                Self::zero(),
                Self::zero(),
                Self::zero(),
                Self(to_monty(124907976)),
            ],
            28 => [
                Self::zero(),
                Self::zero(),
                Self(to_monty(1996171314)),
                Self::zero(),
            ],
            _ => [
                Self::two_adic_generator(bits),
                Self::zero(),
                Self::zero(),
                Self::zero(),
            ],
        }
    }
}

/// Extension of BabyBear field
pub type BabyBearExetension = BinomialExtensionField<BabyBear, 4>;
