/// Precomputes a scaled quotient for faster modular multiplication by a fixed
/// operand.
#[derive(Clone, Copy)]
pub struct MultiplyFactor {
    operand: u64,
    quotient: u64,
}

impl MultiplyFactor {
    /// Computes and stores the scaled quotient `floor((operand << bit_shift) / modulus)`.
    ///
    /// This is useful when modular multiplications of the form `(x * operand) mod modulus`
    /// are performed many times with the same `modulus` and `operand`.
    ///
    /// Note: passing `operand = 1` can be used to precompute a scaled quotient for
    /// multiplications of the form `(x * y) mod modulus`, where only the `modulus`
    /// is reused across calls.
    #[must_use]
    pub fn new(operand: u64, bit_shift: u32, modulus: u64) -> Self {
        assert!(
            operand < modulus,
            "operand {operand} must be less than modulus {modulus}",
        );
        assert!(
            bit_shift == 32 || bit_shift == 52 || bit_shift == 64,
            "Unsupported BitShift {bit_shift}"
        );

        let quotient = (((operand as u128) << bit_shift) / modulus as u128) as u64;

        Self { operand, quotient }
    }

    /// Returns the fixed operand represented by this factor.
    #[must_use]
    pub fn operand(&self) -> u64 {
        self.operand
    }

    /// Returns the precomputed scaled quotient.
    ///
    /// This is floor((operand << bit_shift) / modulus), where bit_shift
    /// and modulus are the values passed to Self::new.
    #[must_use]
    pub fn quotient(&self) -> u64 {
        self.quotient
    }

    /// Returns a lazy representative of this factor's operand times `b` modulo
    /// `modulus`.
    ///
    /// BIT_SHIFT must match the bit_shift value used to construct this
    /// factor, and modulus must match the modulus used to construct it.
    /// Inputs are expected to be canonical modulo modulus, and `modulus` must
    /// be less than `2^(BIT_SHIFT - 2)`. The result lies in
    /// `[0, 2 * modulus)`.
    ///
    /// # Debug assertions
    ///
    /// Debug builds assert the supported `BIT_SHIFT` values and the modulus
    /// bound. Release builds assume callers uphold both contracts.
    #[must_use]
    #[inline]
    pub fn lazy_mul_modulo<const BIT_SHIFT: u32>(self, b: u64, modulus: u64) -> u64 {
        debug_assert!(
            match BIT_SHIFT {
                32 => modulus < (1u64 << 30),
                52 => modulus < (1u64 << 50),
                64 => modulus < (1u64 << 62),
                _ => false,
            },
            "modulus {modulus} must be less than 2^(BIT_SHIFT - 2) for BIT_SHIFT {BIT_SHIFT}",
        );

        let hw = if BIT_SHIFT == 32 {
            (self.quotient * b) >> BIT_SHIFT
        } else {
            ((self.quotient as u128 * b as u128) >> BIT_SHIFT) as u64
        };
        self.operand
            .wrapping_mul(b)
            .wrapping_sub(modulus.wrapping_mul(hw))
    }

    /// Multiplies this factor's operand by b modulo modulus.
    ///
    /// BIT_SHIFT must match the bit_shift value used to construct this
    /// factor, and modulus must match the modulus used to construct it.
    /// Inputs are expected to be canonical modulo modulus, and `modulus` must
    /// be less than `2^(BIT_SHIFT - 2)`.
    #[must_use]
    #[inline]
    pub fn mul_modulo<const BIT_SHIFT: u32>(self, b: u64, modulus: u64) -> u64 {
        let r = self.lazy_mul_modulo::<BIT_SHIFT>(b, modulus);
        r.min(r.wrapping_sub(modulus))
    }
}
