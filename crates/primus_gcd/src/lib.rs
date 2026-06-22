//! Extended GCD and modular inverse for unsigned integer types.
//!
//! This implementation refers to the following codebases.
//! <https://flintlib.org/doc/ulong_extras.html#c.n_xgcd>
//! <https://flintlib.org/doc/ulong_extras.html#c.n_gcdinv>

#![deny(missing_docs)]

/// Lookup table for the modular inverse of an odd `u8` modulo `2^8`.
///
/// `INV_TABLE[((a >> 1) & 0x7F)]` gives the 8-bit inverse of the odd 8-bit
/// number whose lower 8 bits equal those of `a`.  It seeds the Hensel
/// iteration at 8 correct bits instead of 1, removing the first 3 steps.
///
/// Computed from the identity:
///   `INV_TABLE[i] ≡ (2i + 1)^(-1)  (mod 2^8)`   for `i ∈ [0,127]`.
const INV_TABLE: [u8; 128] = [
    1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19, 53, 223, 225, 139, 173, 151, 25,
    131, 165, 207, 209, 251, 29, 135, 9, 243, 21, 191, 193, 107, 141, 119, 249, 99, 133, 175, 177,
    219, 253, 103, 233, 211, 245, 159, 161, 75, 109, 87, 217, 67, 101, 143, 145, 187, 221, 71, 201,
    179, 213, 127, 129, 43, 77, 55, 185, 35, 69, 111, 113, 155, 189, 39, 169, 147, 181, 95, 97, 11,
    45, 23, 153, 3, 37, 79, 81, 123, 157, 7, 137, 115, 149, 63, 65, 235, 13, 247, 121, 227, 5, 47,
    49, 91, 125, 231, 105, 83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93, 199, 73,
    51, 85, 255,
];

/// Greatest common divisor and Bézout coefficients
pub trait Xgcd: Sized {
    /// Calculates the Greatest Common Divisor (GCD) of the number and `other`. The
    /// result is always non-negative.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// assert_eq!(42u64.gcd(56), 14);
    /// assert_eq!(0u64.gcd(5), 5);
    /// assert_eq!(5u64.gcd(0), 5);
    /// ```
    #[must_use]
    fn gcd(self, other: Self) -> Self;

    /// Check whether two numbers are coprime.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// assert!(14u64.is_coprime(25));
    /// assert!(!14u64.is_coprime(28));
    /// assert!(!0u64.is_coprime(0));
    /// ```
    #[must_use]
    #[allow(clippy::wrong_self_convention)]
    fn is_coprime(self, other: Self) -> bool;

    /// Returns the greatest common divisor `g` of `x` and `y` and unsigned
    /// values `a` and `b` such that `a x - b y = g`. We require `x ≥ y`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// let (a, b, d) = u64::xgcd(240, 46);
    /// assert_eq!(d, 2);
    /// assert_eq!(a as u128 * 240 - b as u128 * 46, 2);
    /// ```
    ///
    /// # Panics if
    ///
    /// - `x < y`
    ///
    /// # Algorithm
    ///
    /// We claim that computing the extended greatest common divisor via the
    /// Euclidean algorithm always results in cofactor `|a| < x/2`,
    /// `|b| < x/2`, with perhaps some small degenerate exceptions.
    ///
    /// We proceed by induction.
    ///
    /// Suppose we are at some step of the algorithm, with `x_n = q y_n + r`
    /// with `r ≥ 1`, and suppose `1 = s y_n - t r` with
    /// `s < y_n / 2`, `t < y_n / 2` by hypothesis.
    ///
    /// Write `1 = s y_n - t (x_n - q y_n) = (s + t q) y_n - t x_n`.
    ///
    /// It suffices to show that `(s + t q) < x_n / 2` as `t < y_n / 2 < x_n / 2`,
    /// which will complete the induction step.
    ///
    /// But at the previous step in the back substitution we would have had
    /// `1 = s r - c d` with `s < r/2` and `c < r/2`.
    ///
    /// Then `s + t q < r/2 + y_n / 2 q = (r + q y_n)/2 = x_n / 2`.
    #[must_use]
    fn xgcd(x: Self, y: Self) -> (Self, Self, Self);

    /// Returns the greatest common divisor `g` of `x` and `m` and computes
    /// `a` such that `0 ≤ a < y` and `a x = gcd(x, m) mod m`, when
    /// this is defined. We require `x < m`.
    ///
    /// When `m = 1` the greatest common divisor is set to `1` and `a` is
    /// set to `0`.
    ///
    /// This is merely an adaption of the extended Euclidean algorithm
    /// computing just one cofactor and reducing it modulo `m`.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// let (a, d) = u64::gcdinv(17, 29);
    /// assert_eq!(d, 1);
    /// assert_eq!((a as u128 * 17) % 29, 1);
    /// ```
    ///
    /// # Panics if
    ///
    /// - `x ≥ m`
    #[must_use]
    fn gcdinv(x: Self, m: Self) -> (Self, Self);

    /// Computes the modular inverse of `a` modulo a power of two.
    ///
    /// The modulus is `mask + 1`, where `mask` must be of the form `2^k - 1`
    /// (i.e. the modulus is a power of two). Returns `None` if `a` is even,
    /// since no inverse exists modulo a power of two for even numbers.
    ///
    /// Uses Newton's method (Hensel lifting):
    /// `x_{n+1} = x_n · (2 - a · x_n)  (mod 2^{2^n})`.
    ///
    /// The iteration doubles the number of correct bits each step, converging
    /// in O(log BITS) iterations.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// // modulus = 256, mask = 255
    /// let inv = u64::gcdinv_pow_of_2(3, 255).unwrap();
    /// assert_eq!((inv * 3) & 255, 1);
    /// ```
    #[must_use]
    fn gcdinv_pow_of_2(a: Self, mask: Self) -> Option<Self>;

    /// Computes the modular inverse of `a` modulo `2^BITS` (the full native
    /// word size). Returns `None` if `a` is even.
    ///
    /// Equivalent to `gcdinv_pow_of_2(a, Self::MAX)`, but may avoid an
    /// explicit mask operation.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_gcd::Xgcd;
    ///
    /// let inv = u64::gcdinv_native(3).unwrap();
    /// assert_eq!(inv.wrapping_mul(3), 1);
    /// ```
    #[must_use]
    fn gcdinv_native(a: Self) -> Option<Self>;
}

macro_rules! impl_extended_gcd {
    (impl Xgcd for $SelfT:ty; SignedType: $SignedT:ty) => {
        // Anonymous const block scopes the helper fns so they are reachable
        // from both `xgcd` and `gcdinv` without polluting the module namespace
        // or colliding across the macro's multiple expansions.
        const _: () = {
            // Coefficient recurrences intentionally use limb-width wrapping,
            // matching FLINT's unsigned casts while staying valid in debug builds.
            #[inline]
            fn coeff_sub(lhs: $SignedT, rhs: $SignedT) -> $SignedT {
                lhs.wrapping_sub(rhs)
            }

            #[inline]
            fn coeff_sub_mul(lhs: $SignedT, factor: $SignedT, rhs: $SignedT) -> $SignedT {
                lhs.wrapping_sub(factor.wrapping_mul(rhs))
            }

            impl Xgcd for $SelfT {
                #[inline]
                fn gcd(self, other: Self) -> Self {
                    // Use Stein's algorithm
                    let mut m = self;
                    let mut n = other;
                    if m == 0 || n == 0 {
                        return m | n;
                    }

                    // find common factors of 2
                    let shift = (m | n).trailing_zeros();

                    // divide n and m by 2 until odd
                    m >>= m.trailing_zeros();
                    n >>= n.trailing_zeros();

                    while m != n {
                        if m > n {
                            m -= n;
                            m >>= m.trailing_zeros();
                        } else {
                            n -= m;
                            n >>= n.trailing_zeros();
                        }
                    }
                    m << shift
                }

                #[inline]
                fn is_coprime(self, other: Self) -> bool {
                    // Fast paths that avoid computing the full GCD.
                    if self == other {
                        return self == 1;
                    }
                    if self == 1 || other == 1 {
                        return true;
                    }
                    self.gcd(other) == 1
                }

                #[inline]
                fn xgcd(x: Self, y: Self) -> (Self, Self, Self) {
                    let mut u1: $SignedT;
                    let mut u2: $SignedT;
                    let mut v1: $SignedT;
                    let mut v2: $SignedT;
                    let mut t1: $SignedT;
                    let mut t2: $SignedT;

                    let mut u3: Self;
                    let mut v3: Self;
                    let mut quot: Self;
                    let mut rem: Self;
                    let mut d: Self;

                    assert!(x >= y);

                    u1 = 1;
                    v2 = 1;
                    u2 = 0;
                    v1 = 0;
                    u3 = x;
                    v3 = y;

                    // x and y both have top bit set
                    if ((x & y) as $SignedT) < 0 {
                        d = u3 - v3;
                        t2 = v2;
                        t1 = u2;
                        u2 = coeff_sub(u1, u2);
                        u1 = t1;
                        u3 = v3;
                        v2 = coeff_sub(v1, v2);
                        v1 = t2;
                        v3 = d;
                    }

                    // second value has second msb set
                    while ((v3 << 1) as $SignedT) < 0 {
                        d = u3 - v3;
                        if d < v3 {
                            // quot = 1
                            t2 = v2;
                            t1 = u2;
                            u2 = coeff_sub(u1, u2);
                            u1 = t1;
                            u3 = v3;
                            v2 = coeff_sub(v1, v2);
                            v1 = t2;
                            v3 = d;
                        } else if d < (v3 << 1) {
                            // quot = 2
                            t1 = u2;
                            u2 = coeff_sub_mul(u1, 2, u2);
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 2, v2);
                            v1 = t2;
                            v3 = d - u3;
                        } else {
                            // quot = 3
                            t1 = u2;
                            u2 = coeff_sub_mul(u1, 3, u2);
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 3, v2);
                            v1 = t2;
                            v3 = d - (u3 << 1);
                        }
                    }

                    while v3 > 0 {
                        d = u3 - v3;

                        // overflow not possible, top 2 bits of v3 not set
                        if u3 < (v3 << 2) {
                            if d < v3 {
                                // quot = 1
                                t2 = v2;
                                t1 = u2;
                                u2 = coeff_sub(u1, u2);
                                u1 = t1;
                                u3 = v3;
                                v2 = coeff_sub(v1, v2);
                                v1 = t2;
                                v3 = d;
                            } else if d < (v3 << 1) {
                                // quot = 2
                                t1 = u2;
                                u2 = coeff_sub_mul(u1, 2, u2);
                                u1 = t1;
                                u3 = v3;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 2, v2);
                                v1 = t2;
                                v3 = d - u3;
                            } else {
                                // quot = 3
                                t1 = u2;
                                u2 = coeff_sub_mul(u1, 3, u2);
                                u1 = t1;
                                u3 = v3;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 3, v2);
                                v1 = t2;
                                v3 = d - (u3 << 1);
                            }
                        } else {
                            quot = u3 / v3;
                            rem = u3 - v3 * quot;
                            t1 = u2;
                            u2 = coeff_sub_mul(u1, quot as $SignedT, u2);
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, quot as $SignedT, v2);
                            v1 = t2;
                            v3 = rem;
                        }
                    }

                    /* Remarkably, |u1| < x/2, thus comparison with 0 is valid */
                    if u1 <= 0 {
                        u1 = u1.wrapping_add_unsigned(y);
                        v1 = v1.wrapping_sub_unsigned(x);
                    }

                    (u1 as Self, v1.wrapping_neg() as Self, u3)
                }

                #[inline]
                fn gcdinv(mut x: Self, y: Self) -> (Self, Self) {
                    let mut v1: $SignedT;
                    let mut v2: $SignedT;
                    let mut t2: $SignedT;

                    let mut d: Self;
                    let mut r: Self;
                    let mut quot: Self;
                    let mut rem: Self;

                    assert!(y > x);

                    v1 = 0;
                    v2 = 1;
                    r = x;
                    x = y;

                    // y and x both have top bit set
                    if ((x & r) as $SignedT) < 0 {
                        d = x - r;
                        t2 = v2;
                        x = r;
                        v2 = coeff_sub(v1, v2);
                        v1 = t2;
                        r = d;
                    }

                    // second value has second msb set
                    while ((r << 1) as $SignedT) < 0 {
                        d = x - r;
                        if d < r {
                            // quot = 1
                            t2 = v2;
                            x = r;
                            v2 = coeff_sub(v1, v2);
                            v1 = t2;
                            r = d;
                        } else if d < (r << 1) {
                            // quot = 2
                            x = r;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 2, v2);
                            v1 = t2;
                            r = d - x;
                        } else {
                            // quot = 3
                            x = r;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, 3, v2);
                            v1 = t2;
                            r = d - (x << 1);
                        }
                    }

                    while r > 0 {
                        // overflow not possible due to top 2 bits of r not being set
                        if x < (r << 2) {
                            // if quot < 4
                            d = x - r;
                            if d < r {
                                // quot = 1
                                t2 = v2;
                                x = r;
                                v2 = coeff_sub(v1, v2);
                                v1 = t2;
                                r = d;
                            } else if d < (r << 1) {
                                // quot = 2
                                x = r;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 2, v2);
                                v1 = t2;
                                r = d - x;
                            } else {
                                // quot = 3
                                x = r;
                                t2 = v2;
                                v2 = coeff_sub_mul(v1, 3, v2);
                                v1 = t2;
                                r = d - (x << 1);
                            }
                        } else {
                            quot = x / r;
                            rem = x - r * quot;
                            x = r;
                            t2 = v2;
                            v2 = coeff_sub_mul(v1, quot as $SignedT, v2);
                            v1 = t2;
                            r = rem;
                        }
                    }

                    if v1 < 0 {
                        v1 = v1.wrapping_add_unsigned(y);
                    }

                    (v1 as Self, x)
                }

                #[inline]
                fn gcdinv_pow_of_2(a: Self, mask: Self) -> Option<Self> {
                    const TWO: $SelfT = 2;
                    if a & 0b1 == 0 {
                        return None;
                    }

                    let mut x: $SelfT = INV_TABLE[((a >> 1) & 0x7F) as usize] as $SelfT;
                    for _ in 2..Self::BITS.ilog2() {
                        x = x.wrapping_mul(TWO.wrapping_sub(a.wrapping_mul(x)));
                    }
                    Some(x & mask)
                }

                #[inline]
                fn gcdinv_native(a: Self) -> Option<Self> {
                    const TWO: $SelfT = 2;
                    if a & 0b1 == 0 {
                        return None;
                    }

                    let mut x: $SelfT = INV_TABLE[((a >> 1) & 0x7F) as usize] as $SelfT;
                    for _ in 2..Self::BITS.ilog2() {
                        x = x.wrapping_mul(TWO.wrapping_sub(a.wrapping_mul(x)));
                    }
                    Some(x)
                }
            }
        };
    };
}

impl_extended_gcd!(impl Xgcd for u8; SignedType: i8);
impl_extended_gcd!(impl Xgcd for u16; SignedType: i16);
impl_extended_gcd!(impl Xgcd for u32; SignedType: i32);
impl_extended_gcd!(impl Xgcd for u64; SignedType: i64);
impl_extended_gcd!(impl Xgcd for usize; SignedType: isize);
impl_extended_gcd!(impl Xgcd for u128; SignedType: i128);

#[cfg(test)]
mod tests {
    use rand::{prelude::*, rngs::StdRng};

    use super::*;

    const RANDOM_CASES: usize = 128;
    const MSB_RANDOM_CASES: usize = 64;

    fn seeded_rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    macro_rules! gcd_edge_tests {
        ($mod_name:ident, $T:ty) => {
            mod $mod_name {
                use super::*;

                // Checks GCD behavior when either or both inputs are zero.
                #[test]
                fn test_gcd_zero() {
                    assert_eq!(<$T>::gcd(0 as $T, 0 as $T), 0 as $T);
                    assert_eq!(<$T>::gcd(42 as $T, 0 as $T), 42 as $T);
                    assert_eq!(<$T>::gcd(0 as $T, 42 as $T), 42 as $T);
                }

                // Checks GCD behavior when one or both inputs are one.
                #[test]
                fn test_gcd_one() {
                    assert_eq!(<$T>::gcd(1 as $T, 1 as $T), 1 as $T);
                    assert_eq!(<$T>::gcd(1 as $T, 42 as $T), 1 as $T);
                    assert_eq!(<$T>::gcd(42 as $T, 1 as $T), 1 as $T);
                }

                // Checks that GCD is symmetric over full-range random inputs.
                #[test]
                fn test_gcd_symmetry() {
                    let mut rng = seeded_rng(0x6763_645f_7379_6d6d);
                    for _ in 0..RANDOM_CASES {
                        let a = rng.random_range(<$T>::MIN..=<$T>::MAX);
                        let b = rng.random_range(<$T>::MIN..=<$T>::MAX);
                        assert_eq!(a.gcd(b), b.gcd(a));
                    }
                }

                // Checks coprimality semantics around zero and one.
                #[test]
                fn test_is_coprime_zero() {
                    assert!(!<$T>::is_coprime(0 as $T, 0 as $T));
                    assert!(<$T>::is_coprime(0 as $T, 1 as $T));
                    assert!(<$T>::is_coprime(1 as $T, 0 as $T));
                    assert!(<$T>::is_coprime(1 as $T, 1 as $T));
                }

                // Checks that xgcd returns the same divisor as gcd.
                #[test]
                fn test_xgcd_d_is_gcd() {
                    let mut rng = seeded_rng(0x7867_6364_5f64_6763);
                    for _ in 0..RANDOM_CASES {
                        let x = rng.random_range(<$T>::MIN..=<$T>::MAX);
                        let y = rng.random_range(<$T>::MIN..=x);
                        let (_a, _b, d) = <$T>::xgcd(x, y);
                        assert_eq!(d, x.gcd(y));
                    }
                }

                // Checks simple Bezout edge cases for xgcd.
                #[test]
                fn test_xgcd_bezout() {
                    let mut rng = seeded_rng(0x7867_6364_5f62_657a);

                    // x = y: d = x, and a*x - b*x = x => (a - b) = 1
                    let x = rng.random_range((2 as $T)..=<$T>::MAX);
                    let (_a, _b, d) = <$T>::xgcd(x, x);
                    assert_eq!(d, x);

                    // y = 1: gcd(x, 1) = 1
                    let (a, _b, d) = <$T>::xgcd(x, 1 as $T);
                    assert_eq!(d, 1 as $T);
                    assert!(a < x);
                }

                // Checks that gcdinv returns the same divisor as gcd.
                #[test]
                fn test_gcdinv_d_is_gcd() {
                    let mut rng = seeded_rng(0x6769_6e76_5f64_6763);
                    for _ in 0..RANDOM_CASES {
                        let y = rng.random_range((1 as $T)..=<$T>::MAX);
                        let x = rng.random_range(<$T>::MIN..y);
                        let (a, d) = <$T>::gcdinv(x, y);
                        assert_eq!(d, x.gcd(y));
                        assert!(a < y, "a={a} should be < y={y}");
                    }
                }

                // Checks gcdinv behavior when the input value is zero.
                #[test]
                fn test_gcdinv_edge() {
                    // x = 0
                    let mut rng = seeded_rng(0x6769_6e76_5f65_6467);
                    let y = rng.random_range((1 as $T)..=<$T>::MAX);
                    let (a, d) = <$T>::gcdinv(0 as $T, y);
                    assert_eq!(d, y);
                    assert!(a < y);
                }

                // Checks the high-quotient xgcd path that used to overflow in debug builds.
                #[test]
                fn test_xgcd_high_quotient_boundary() {
                    let x = (<$T>::MAX >> 1) + (1 as $T);
                    let (a, b, d) = <$T>::xgcd(x, 1 as $T);
                    assert_eq!(a, 1 as $T);
                    assert_eq!(b, x - (1 as $T));
                    assert_eq!(d, 1 as $T);
                }

                // Checks the high-quotient gcdinv path that used to overflow in debug builds.
                #[test]
                fn test_gcdinv_high_quotient_boundary() {
                    let y = (<$T>::MAX >> 1) + (1 as $T);
                    let (a, d) = <$T>::gcdinv(1 as $T, y);
                    assert_eq!(a, 1 as $T);
                    assert_eq!(d, 1 as $T);
                }

                // gcdinv_pow_of_2: even input returns None.
                #[test]
                fn test_gcdinv_pow_of_2_even() {
                    assert_eq!(<$T>::gcdinv_pow_of_2(0 as $T, <$T>::MAX), None);
                    assert_eq!(<$T>::gcdinv_pow_of_2(2 as $T, <$T>::MAX), None);
                    assert_eq!(<$T>::gcdinv_pow_of_2(42 as $T, <$T>::MAX), None);
                }

                // gcdinv_pow_of_2: (inverse * a) ≡ 1 (mod mask+1).
                #[test]
                fn test_gcdinv_pow_of_2_identity() {
                    let mut rng = seeded_rng(0x706f_775f_3269_6e76);
                    for _ in 0..RANDOM_CASES {
                        // Pick an odd a.
                        let a = rng.random_range(<$T>::MIN..=<$T>::MAX) | 1;
                        // Pick a random power-of-two modulus via mask.
                        let k = rng.random_range(1..<$T>::BITS);
                        let mask = if k == <$T>::BITS {
                            <$T>::MAX
                        } else {
                            ((1 as $T) << k).wrapping_sub(1)
                        };
                        let inv = <$T>::gcdinv_pow_of_2(a, mask).unwrap();
                        assert_eq!(
                            (inv.wrapping_mul(a)) & mask,
                            1 & mask,
                            "a={a}, k={k}, inv={inv}",
                        );
                    }
                }

                // gcdinv_pow_of_2: mask = 0 (modulus = 1) — inverse of anything is 0.
                #[test]
                fn test_gcdinv_pow_of_2_mask_one() {
                    // modulus = 1, mask = 0. The only value mod 1 is 0.
                    let mut rng = seeded_rng(0x6d61_736b_5f6f_6e65);
                    let a = rng.random_range(<$T>::MIN..=<$T>::MAX) | 1;
                    let inv = <$T>::gcdinv_pow_of_2(a, 0 as $T).unwrap();
                    assert_eq!(inv, 0 as $T);
                }

                // gcdinv_native: even input returns None.
                #[test]
                fn test_gcdinv_native_even() {
                    assert_eq!(<$T>::gcdinv_native(0 as $T), None);
                    assert_eq!(<$T>::gcdinv_native(2 as $T), None);
                    assert_eq!(<$T>::gcdinv_native(100 as $T), None);
                }

                // gcdinv_native: inverse.wrapping_mul(a) == 1.
                #[test]
                fn test_gcdinv_native_identity() {
                    let mut rng = seeded_rng(0x6e61_7469_7665_6964);
                    for _ in 0..RANDOM_CASES {
                        let a = rng.random_range(<$T>::MIN..=<$T>::MAX) | 1;
                        let inv = <$T>::gcdinv_native(a).unwrap();
                        assert_eq!(inv.wrapping_mul(a), 1 as $T, "a={a}, inv={inv}",);
                    }
                }
            }
        };
    }

    macro_rules! gcd_identity_tests {
        ($mod_name:ident, $T:ty, $WideT:ty) => {
            mod $mod_name {
                use super::*;

                // Checks the full Bezout identity for xgcd using a wider integer type.
                #[test]
                fn test_xgcd_identity() {
                    let mut rng = seeded_rng(0x7867_6364_5f69_6465);
                    for _ in 0..RANDOM_CASES {
                        let x = rng.random_range(<$T>::MIN..=<$T>::MAX);
                        let y = rng.random_range(0..=x);
                        let (a, b, d) = <$T>::xgcd(x, y);
                        assert_eq!(
                            a as $WideT * x as $WideT - b as $WideT * y as $WideT,
                            d as $WideT,
                            "x={x}, y={y}, a={a}, b={b}, d={d}",
                        );
                    }
                }

                // Checks the modular inverse identity for gcdinv using a wider integer type.
                #[test]
                fn test_gcdinv_identity() {
                    let mut rng = seeded_rng(0x6769_6e76_5f69_6465);
                    for _ in 0..RANDOM_CASES {
                        let y = rng.random_range(1..=<$T>::MAX);
                        let x = rng.random_range(0..y);
                        let (a, d) = <$T>::gcdinv(x, y);
                        assert_eq!(
                            (a as $WideT * x as $WideT) % y as $WideT,
                            d as $WideT % y as $WideT,
                            "x={x}, y={y}, a={a}, d={d}",
                        );
                    }
                }
            }
        };
    }

    // Edge case tests for all types, including u128
    gcd_edge_tests!(tests_u8, u8);
    gcd_edge_tests!(tests_u16, u16);
    gcd_edge_tests!(tests_u32, u32);
    gcd_edge_tests!(tests_u64, u64);
    gcd_edge_tests!(tests_usize, usize);
    gcd_edge_tests!(tests_u128, u128);

    // Identity tests (a*x - b*y = d) -- only for types that have a wider type
    gcd_identity_tests!(tests_id_u8, u8, u16);
    gcd_identity_tests!(tests_id_u16, u16, u32);
    gcd_identity_tests!(tests_id_u32, u32, u64);
    gcd_identity_tests!(tests_id_u64, u64, u128);
    #[cfg(target_pointer_width = "32")]
    gcd_identity_tests!(tests_id_usize, usize, u64);
    #[cfg(target_pointer_width = "64")]
    gcd_identity_tests!(tests_id_usize, usize, u128);

    macro_rules! gcd_msb_tests {
        ($mod_name:ident, $T:ty, $WideT:ty) => {
            mod $mod_name {
                use super::*;

                // Checks xgcd when both operands have the top bit set.
                #[test]
                fn test_xgcd_msb_both() {
                    // Path A: both operands have the MSB set, triggering
                    // `(x & y) as signed < 0`.  We pick the smallest values
                    // with the MSB set (x = y = MAX>>1 + 1): xgcd(x, x)
                    // hits the first-if and exits immediately (v3 = 0),
                    // avoiding the quot=3 branch in the main loop.
                    let val = (<$T>::MAX >> 1) + 1;
                    let (a, b, d) = <$T>::xgcd(val, val);
                    assert_eq!(d, val);
                    assert!(
                        a >= 1 && a.wrapping_sub(1) == b,
                        "a={a}, b={b}, expected a-b=1"
                    );
                }

                // Checks xgcd when the second operand has the second MSB set.
                #[test]
                fn test_xgcd_msb_second() {
                    // Path B: second MSB set but top MSB clear, triggering
                    // `(v3 << 1) as signed < 0`.  Range [MAX>>2+1, MAX>>1]
                    // is safe: cofactor bound x/2 < MAX/4, so 3*x/2 <
                    // 3*MAX/8 which fits in the signed type.
                    let mut rng = seeded_rng(0x6d73_625f_7867_6364);
                    let lo = (<$T>::MAX >> 2) + 1;
                    let hi = <$T>::MAX >> 1;
                    for _ in 0..MSB_RANDOM_CASES {
                        let x = rng.random_range(lo..=hi);
                        let y = rng.random_range(lo..=x);
                        let (a, b, d) = <$T>::xgcd(x, y);
                        assert_eq!(d, x.gcd(y));
                        let lhs = a as $WideT * x as $WideT - b as $WideT * y as $WideT;
                        assert_eq!(lhs, d as $WideT);
                    }
                }

                // Checks gcdinv when the modulus has the second MSB set.
                #[test]
                fn test_gcdinv_msb_second() {
                    let mut rng = seeded_rng(0x6d73_625f_6769_6e76);
                    let lo = (<$T>::MAX >> 2) + 1;
                    let hi = <$T>::MAX >> 1;
                    for _ in 0..MSB_RANDOM_CASES {
                        let y = rng.random_range((lo + (1 as $T))..=hi);
                        let x = rng.random_range(lo..y);
                        let (a, d) = <$T>::gcdinv(x, y);
                        assert_eq!(d, x.gcd(y));
                        assert_eq!(
                            (a as $WideT * x as $WideT) % y as $WideT,
                            d as $WideT % y as $WideT,
                        );
                    }
                }
            }
        };
    }

    // MSB tests for types that have a wider type for identity checks.
    gcd_msb_tests!(tests_msb_u8, u8, u16);
    gcd_msb_tests!(tests_msb_u16, u16, u32);
    gcd_msb_tests!(tests_msb_u32, u32, u64);
    gcd_msb_tests!(tests_msb_u64, u64, u128);

    mod exhaustive_u8 {
        use super::*;

        // Exhaustively checks the xgcd Bezout identity for every valid u8 input pair.
        #[test]
        fn test_xgcd_exhaustive_identity() {
            for x in u8::MIN..=u8::MAX {
                for y in u8::MIN..=x {
                    let (a, b, d) = u8::xgcd(x, y);
                    assert_eq!(d, x.gcd(y), "x={x}, y={y}, a={a}, b={b}");
                    assert_eq!(
                        a as u16 * x as u16 - b as u16 * y as u16,
                        d as u16,
                        "x={x}, y={y}, a={a}, b={b}, d={d}",
                    );
                }
            }
        }

        // Exhaustively checks the gcdinv modular identity for every valid u8 input pair.
        #[test]
        fn test_gcdinv_exhaustive_identity() {
            for y in 1..=u8::MAX {
                for x in u8::MIN..y {
                    let (a, d) = u8::gcdinv(x, y);
                    assert_eq!(d, x.gcd(y), "x={x}, y={y}, a={a}");
                    assert!(a < y, "x={x}, y={y}, a={a}");
                    assert_eq!(
                        (a as u16 * x as u16) % y as u16,
                        d as u16 % y as u16,
                        "x={x}, y={y}, a={a}, d={d}",
                    );
                }
            }
        }

        // Exhaustively checks gcdinv_pow_of_2 for every odd u8 and every
        // power-of-two modulus (k = 1..=8).
        #[test]
        fn test_gcdinv_pow_of_2_exhaustive_identity() {
            for a in (1..=u8::MAX).step_by(2) {
                for k in 1..=8 {
                    let mask: u8 = if k == 8 { u8::MAX } else { (1u8 << k) - 1 };
                    let inv = u8::gcdinv_pow_of_2(a, mask).unwrap();
                    assert_eq!(
                        (inv.wrapping_mul(a)) & mask,
                        1 & mask,
                        "a={a}, k={k}, inv={inv}",
                    );
                }
            }
        }

        // Exhaustively checks gcdinv_native for every odd u8.
        #[test]
        fn test_gcdinv_native_exhaustive_identity() {
            for a in (1..=u8::MAX).step_by(2) {
                let inv = u8::gcdinv_native(a).unwrap();
                assert_eq!(inv.wrapping_mul(a), 1u8, "a={a}, inv={inv}",);
            }
        }
    }

    mod tests_msb_u128 {
        use super::*;

        // Checks the u128 xgcd path where both operands have the top bit set.
        #[test]
        fn test_xgcd_msb_both() {
            // Path A: both operands MSB set, using minimal values to avoid
            // the quot=3 branch in the main loop.
            let val = (u128::MAX >> 1) + 1;
            let (a, b, d) = u128::xgcd(val, val);
            assert_eq!(d, val);
            assert!(a >= 1 && a.wrapping_sub(1) == b);
        }

        // Checks the u128 xgcd path where the second operand has the second MSB set.
        #[test]
        fn test_xgcd_msb_second() {
            // Path B: second MSB set, top MSB clear.
            let mut rng = seeded_rng(0x6d73_625f_7531_3238);
            let lo = (u128::MAX >> 2) + 1;
            let hi = u128::MAX >> 1;
            for _ in 0..MSB_RANDOM_CASES {
                let x = rng.random_range(lo..=hi);
                let y = rng.random_range(lo..=x);
                let (_a, _b, d) = u128::xgcd(x, y);
                assert_eq!(d, x.gcd(y));
            }
        }

        // Checks the u128 gcdinv path where the modulus has the second MSB set.
        #[test]
        fn test_gcdinv_msb_second() {
            let mut rng = seeded_rng(0x6769_6e76_7531_3238);
            let lo = (u128::MAX >> 2) + 1;
            let hi = u128::MAX >> 1;
            for _ in 0..MSB_RANDOM_CASES {
                let y = rng.random_range((lo + 1)..=hi);
                let x = rng.random_range(lo..y);
                let (a, d) = u128::gcdinv(x, y);
                assert_eq!(d, x.gcd(y));
                assert!(a < y);
            }
        }
    }
}
