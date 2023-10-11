macro_rules! impl_prime_modulus {
    (impl PrimeModulus<$SelfT:ty>; WideType: $WideT:ty) => {
        impl PrimeModulus<$SelfT> {
            /// Creates a [`PrimeModulus<T>`] instance.
            ///
            /// - `value`: The value of the modulus.
            ///
            /// # Panics
            ///
            #[doc = concat!("The `value`'s `bit_count` should be at most ", stringify!($SelfT::BITS - 1), ", others will panic.")]
            pub const fn new(value: $SelfT) -> Self {
                const HALF_BITS: u32 = <$SelfT>::BITS >> 1;
                const HALF: $SelfT = (1 << HALF_BITS) - 1;

                #[inline]
                const fn div_rem(numerator: $SelfT, divisor: $SelfT) -> ($SelfT, $SelfT) {
                    (numerator / divisor, numerator % divisor)
                }

                #[inline]
                const fn div_wide(hi: $SelfT, lo: $SelfT, divisor: $SelfT) -> ($SelfT, $SelfT) {
                    debug_assert!(hi < divisor);
                    let lhs = lo as $WideT | ((hi as $WideT) << <$SelfT>::BITS);
                    let rhs = divisor as $WideT;
                    ((lhs / rhs) as $SelfT, (lhs % rhs) as $SelfT)
                }

                #[inline]
                const fn div_half(rem: $SelfT, digit: $SelfT, divisor: $SelfT) -> ($SelfT, $SelfT) {
                    debug_assert!(rem < divisor && divisor <= HALF);
                    let (hi, rem) = div_rem((rem << HALF_BITS) | (digit >> HALF_BITS), divisor);
                    let (lo, rem) = div_rem((rem << HALF_BITS) | (digit & HALF), divisor);
                    ((hi << HALF_BITS) | lo, rem)
                }

                const fn div_inplace(value: $SelfT) -> ([$SelfT; 3], $SelfT) {
                    assert!(value != 0);

                    let mut numerator = [0, 0, 0];
                    let mut rem = 0;

                    if value <= HALF {
                        let (q, r) = div_half(rem, 1, value);
                        numerator[2] = q;
                        rem = r;

                        let (q, r) = div_half(rem, 0, value);
                        numerator[1] = q;
                        rem = r;

                        let (q, r) = div_half(rem, 0, value);
                        numerator[0] = q;
                        rem = r;
                    } else {
                        let (q, r) = div_wide(rem, 1, value);
                        numerator[2] = q;
                        rem = r;

                        let (q, r) = div_wide(rem, 0, value);
                        numerator[1] = q;
                        rem = r;

                        let (q, r) = div_wide(rem, 0, value);
                        numerator[0] = q;
                        rem = r;
                    }
                    (numerator, rem)
                }

                match value {
                    0 | 1 => panic!("modulus can't be 0 or 1."),
                    _ => {
                        let bit_count = <$SelfT>::BITS - value.leading_zeros();
                        assert!(bit_count < <$SelfT>::BITS);

                        let (numerator, _) = div_inplace(value);

                        Self {
                            value,
                            ratio: [numerator[0], numerator[1]],
                            bit_count,
                        }
                    }
                }
            }
        }

        impl crate::modulo::Modulo<&PrimeModulus<$SelfT>> for $SelfT {
            type Output = Self;

            /// Caculates `self (mod modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            fn modulo(self, modulus: &PrimeModulus<$SelfT>) -> Self::Output {
                let ratio = modulus.ratio();

                // Step 1.
                //              ratio[1]  ratio[0]
                //         *                self
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //            +-------------------+
                //            |  tmp1   |         |    <-- self * ratio[0]
                //            +-------------------+
                //   +------------------+
                //   |      tmp2        |              <-- self * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +--------+
                //   |   q3   |
                //   +--------+
                let tmp = (self as $WideT * ratio[0] as $WideT) >> <$SelfT>::BITS; // tmp1
                let tmp = ((self as $WideT * ratio[1] as $WideT + tmp) >> <$SelfT>::BITS) as $SelfT; // q3

                // Step 2.
                let tmp = self.wrapping_sub(tmp.wrapping_mul(modulus.value())); // r = r1 -r2

                // Step 3. and 4.
                if tmp >= modulus.value() {
                    tmp - modulus.value()
                } else {
                    tmp
                }
            }
        }

        impl crate::modulo::Modulo<&PrimeModulus<$SelfT>> for [$SelfT; 2] {
            type Output = $SelfT;

            /// Caculates `self (mod modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            fn modulo(self, modulus: &PrimeModulus<$SelfT>) -> Self::Output {
                let ratio = modulus.ratio();

                // Step 1.
                //                        ratio[1]  ratio[0]
                //                   *    value[1]  value[0]
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //                      +-------------------+
                //                      |         a         |    <-- value[0] * ratio[0]
                //                      +-------------------+
                //             +------------------+
                //             |        b         |              <-- value[0] * ratio[1]
                //             +------------------+
                //             +------------------+
                //             |        c         |              <-- value[1] * ratio[0]
                //             +------------------+
                //   +------------------+
                //   |        d         |                        <-- value[1] * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +------------------+
                //   |        q3        |
                //   +------------------+
                let a = ratio[0] as $WideT * self[0] as $WideT;
                let b_plus_a_left = ratio[1] as $WideT * self[0] as $WideT + (a >> <$SelfT>::BITS);

                let c = ratio[0] as $WideT * self[1] as $WideT;
                let d = ratio[1] as $WideT * self[1] as $WideT;

                let tmp = d.wrapping_add((b_plus_a_left + c) >> <$SelfT>::BITS) as $SelfT;

                // Step 2.
                let r = self[0].wrapping_sub(tmp.wrapping_mul(modulus.value()));

                // Step 3. and 4.
                if r >= modulus.value() {
                    r - modulus.value()
                } else {
                    r
                }
            }
        }

        impl crate::modulo::Modulo<&PrimeModulus<$SelfT>> for ($SelfT, $SelfT) {
            type Output = $SelfT;

            /// Caculates `self (mod modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            fn modulo(self, modulus: &PrimeModulus<$SelfT>) -> Self::Output {
                let ratio = modulus.ratio();

                // Step 1.
                //                        ratio[1]  ratio[0]
                //                   *    value.1   value.0
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //                      +-------------------+
                //                      |         a         |    <-- value.0 * ratio[0]
                //                      +-------------------+
                //             +------------------+
                //             |        b         |              <-- value.0 * ratio[1]
                //             +------------------+
                //             +------------------+
                //             |        c         |              <-- value.1 * ratio[0]
                //             +------------------+
                //   +------------------+
                //   |        d         |                        <-- value.1 * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +------------------+
                //   |        q3        |
                //   +------------------+
                let a = ratio[0] as $WideT * self.0 as $WideT;
                let b_plus_a_left = ratio[1] as $WideT * self.0 as $WideT + (a >> <$SelfT>::BITS);

                let c = ratio[0] as $WideT * self.1 as $WideT;
                let d = ratio[1] as $WideT * self.1 as $WideT;

                let tmp = d.wrapping_add((b_plus_a_left + c) >> <$SelfT>::BITS) as $SelfT;

                // Step 2.
                let r = self.0.wrapping_sub(tmp.wrapping_mul(modulus.value()));

                // Step 3. and 4.
                if r >= modulus.value() {
                    r - modulus.value()
                } else {
                    r
                }
            }
        }

        impl crate::modulo::Modulo<&PrimeModulus<$SelfT>> for &[$SelfT] {
            type Output = $SelfT;

            /// Caculates `self (mod modulus)` when value's length > 0.
            fn modulo(self, modulus: &PrimeModulus<$SelfT>) -> Self::Output {
                match self {
                    &[] => unreachable!(),
                    &[v] => {
                        if v < modulus.value() {
                            v
                        } else {
                            v.modulo(modulus)
                        }
                    }
                    [other @ .., last] => other
                        .iter()
                        .rfold(*last, |acc, x| [*x, acc].modulo(modulus)),
                }
            }
        }

        impl crate::modulo::ModuloAssign<&PrimeModulus<$SelfT>> for $SelfT {
            /// Caculates `self (mod modulus)`.
            ///
            /// ## Procedure
            ///
            /// We denote `x` = `self`  and `m` = `modulus` here.
            ///
            /// The algorithm will output `r` = `x` mod `m` with the below procedures:
            ///
            /// 1. `q1` ← `x`, `q2` ← `q1` * `ratio`, `q3` ← ⌊`q2`/b^2⌋.
            /// 2. `r1` ← `x` mod b^2, `r2` ← `q3` * `m` mod b^2, `r` ← `r1` − `r2`.
            /// 3. If `r` ≥ `m` do: `r` ← `r` − `m`.
            /// 4. Return(`r`).
            ///
            /// ## Proof:
            ///
            /// ∵ `q1` = `x` , ⌊b^2 / m⌋ - 1 < `ratio` ≤ ⌊b^2 / m⌋
            ///
            /// ∴ ⌊x * b^2 / m⌋ - x < `q2` = `q1` * `ratio` ≤ ⌊x * b^2 / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 2 < `q3` = ⌊`q2` / b^2⌋ ≤ ⌊x / m⌋
            ///
            /// ∴ ⌊x / m⌋ - 1 ≤ `q3` ≤ ⌊x / m⌋
            ///
            /// ∴ `x` - `q3` * `m` mod b^2 < 2 * m
            fn modulo_assign(&mut self, modulus: &PrimeModulus<$SelfT>) {
                let ratio = modulus.ratio();

                // Step 1.
                //              ratio[1]  ratio[0]
                //         *                self
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //            +-------------------+
                //            |  tmp1   |         |    <-- self * ratio[0]
                //            +-------------------+
                //   +------------------+
                //   |      tmp2        |              <-- self * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +--------+
                //   |   q3   |
                //   +--------+
                let tmp = (*self as $WideT * ratio[0] as $WideT) >> <$SelfT>::BITS; // tmp1
                let tmp =
                    ((*self as $WideT * ratio[1] as $WideT + tmp) >> <$SelfT>::BITS) as $SelfT; // q3

                // Step 2.
                *self = self.wrapping_sub(tmp.wrapping_mul(modulus.value())); // r = r1 -r2

                // Step 3. and 4.
                if *self >= modulus.value() {
                    *self -= modulus.value();
                }
            }
        }
    };
}
