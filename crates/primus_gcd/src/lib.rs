//! Greatest-common-divisor and modular-inverse operations for primitive
//! unsigned integers.
//!
//! The [`Xgcd`] extension trait is implemented for `u8`, `u16`, `u32`, `u64`,
//! `u128`, and `usize`. It provides ordinary GCD and coprimality operations,
//! extended-GCD coefficients normalized as `a * x - b * y = gcd(x, y)`, and
//! modular inverses for both general and power-of-two moduli.
//!
//! The implementations use fixed-width, allocation-free arithmetic. The
//! general extended-GCD routines are based on FLINT's unsigned-integer
//! algorithms, while power-of-two inversion uses Newton/Hensel lifting.
//!
//! # References
//!
//! - FLINT [`n_xgcd`](https://flintlib.org/doc/ulong_extras.html#c.n_xgcd)
//! - FLINT [`n_gcdinv`](https://flintlib.org/doc/ulong_extras.html#c.n_gcdinv)

#![deny(missing_docs)]

/// Lookup table for inverses of odd integers modulo `2^8`.
///
/// For odd `a`, `INV_TABLE[((a >> 1) & 0x7F) as usize]` is the inverse of
/// `a` modulo `2^8`. This supplies eight correct low bits to the Hensel
/// iteration and skips the first three one-bit-seeded lifting steps.
///
/// Each entry satisfies `INV_TABLE[i] * (2 * i + 1) ≡ 1 (mod 2^8)` for
/// `i` in `0..128`.
const INV_TABLE: [u8; 128] = [
    1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19, 53, 223, 225, 139, 173, 151, 25,
    131, 165, 207, 209, 251, 29, 135, 9, 243, 21, 191, 193, 107, 141, 119, 249, 99, 133, 175, 177,
    219, 253, 103, 233, 211, 245, 159, 161, 75, 109, 87, 217, 67, 101, 143, 145, 187, 221, 71, 201,
    179, 213, 127, 129, 43, 77, 55, 185, 35, 69, 111, 113, 155, 189, 39, 169, 147, 181, 95, 97, 11,
    45, 23, 153, 3, 37, 79, 81, 123, 157, 7, 137, 115, 149, 63, 65, 235, 13, 247, 121, 227, 5, 47,
    49, 91, 125, 231, 105, 83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93, 199, 73,
    51, 85, 255,
];

/// Extension trait for GCD, coprimality, Bézout coefficients, and modular
/// inverses.
pub trait Xgcd: Sized {
    /// Returns the greatest common divisor of `self` and `other`.
    ///
    /// By convention, `gcd(0, 0) = 0`.
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

    /// Returns `true` if `self` and `other` are coprime.
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

    /// Returns `(a, b, g)`, where `g` is the greatest common divisor of `x`
    /// and `y`, and the unsigned coefficients satisfy `a * x - b * y = g` over
    /// the integers. Requires `x >= y`.
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
    /// # Panics
    ///
    /// Panics if `x < y`.
    ///
    /// # Algorithm
    ///
    /// Uses the extended Euclidean algorithm with specialized paths for the
    /// small quotients `1`, `2`, and `3`. The coefficient signs are normalized
    /// to the returned unsigned form `a * x - b * y = g`.
    #[must_use]
    fn xgcd(x: Self, y: Self) -> (Self, Self, Self);

    /// Returns `(a, g)`, where `g = gcd(x, m)`, `0 <= a < m`, and
    /// `a * x ≡ g (mod m)`. Requires `x < m`.
    ///
    /// When `g = 1`, `a` is the multiplicative inverse of `x` modulo `m`.
    ///
    /// When `m = 1`, this method returns `(0, 1)`.
    ///
    /// The implementation adapts the extended Euclidean algorithm to track
    /// only the required coefficient and normalize it modulo `m`.
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
    /// # Panics
    ///
    /// Panics if `x >= m`.
    #[must_use]
    fn gcdinv(x: Self, m: Self) -> (Self, Self);

    /// Computes the modular inverse of `a` modulo `2^k`.
    ///
    /// `mask` specifies the modulus and must equal `2^k - 1` for
    /// `1 <= k <= Self::BITS`. When `k = Self::BITS`, the modulus is the full
    /// native wrapping modulus even though `2^Self::BITS` is not representable
    /// by `Self`. Returns `None` if `a` is even, since only odd integers are
    /// invertible modulo a nontrivial power of two.
    ///
    /// Uses the Newton/Hensel update `x <- x * (2 - a * x)`. Each iteration
    /// doubles the number of correct low bits.
    ///
    /// The iteration converges in `O(log(Self::BITS))` steps.
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
    ///
    /// # Panics
    ///
    /// Panics if `mask` is zero or is not of the form `2^k - 1`.
    #[must_use]
    fn gcdinv_pow_of_2(a: Self, mask: Self) -> Option<Self>;

    /// Computes the modular inverse of `a` modulo `2^Self::BITS` using native
    /// wrapping arithmetic. Returns `None` if `a` is even.
    ///
    /// Equivalent to [`Self::gcdinv_pow_of_2`] with `mask = Self::MAX`, but may
    /// avoid an explicit mask operation.
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
        // A const block gives each macro expansion its own helper-function
        // scope, keeping the generated names out of the module namespace and
        // preventing collisions between integer types.
        const _: () = {
            // Coefficient recurrences intentionally use word-width two's-complement
            // wrapping, matching FLINT's casts while avoiding debug overflow panics.
            #[inline]
            fn coeff_sub(lhs: $SignedT, rhs: $SignedT) -> $SignedT {
                lhs.wrapping_sub(rhs)
            }

            #[inline]
            fn coeff_sub_mul(lhs: $SignedT, factor: $SignedT, rhs: $SignedT) -> $SignedT {
                lhs.wrapping_sub(factor.wrapping_mul(rhs))
            }

            #[inline(always)]
            fn lift_inverse(a: $SelfT, x: $SelfT) -> $SelfT {
                const TWO: $SelfT = 2;

                // If `a * x = 1` modulo `2^b`, this Newton step makes the
                // product equal to one modulo `2^(2b)`.
                x.wrapping_mul(TWO.wrapping_sub(a.wrapping_mul(x)))
            }

            /// Lift the table inverse to the full word; the caller has established that a is odd.
            #[inline(always)]
            fn inverse_odd_mod_native(a: $SelfT) -> $SelfT {
                // The table supplies eight correct bits; every lift doubles
                // that precision until it covers the native word.
                let mut x = INV_TABLE[((a >> 1) & 0x7F) as usize] as $SelfT;
                for _ in 3..<$SelfT>::BITS.ilog2() {
                    x = lift_inverse(a, x);
                }
                x
            }

            /// Lift only as far as needed; a is odd and mask is a validated 2^k - 1.
            #[inline(always)]
            fn inverse_odd_mod_mask(a: $SelfT, mask: $SelfT) -> $SelfT {
                // Stop as soon as the lifted precision covers the modulus
                // selected by `mask`, then discard any excess high bits.
                let mut x = INV_TABLE[((a >> 1) & 0x7F) as usize] as $SelfT;
                if mask <= u8::MAX as $SelfT {
                    return x & mask;
                }

                x = lift_inverse(a, x);
                if mask <= u16::MAX as $SelfT {
                    return x & mask;
                }

                x = lift_inverse(a, x);
                if mask <= u32::MAX as $SelfT {
                    return x & mask;
                }

                x = lift_inverse(a, x);
                if mask <= u64::MAX as $SelfT {
                    return x & mask;
                }

                lift_inverse(a, x) & mask
            }

            impl Xgcd for $SelfT {
                #[inline]
                fn gcd(self, other: Self) -> Self {
                    // Use Stein's binary GCD algorithm.
                    let mut m = self;
                    let mut n = other;
                    if m == 0 || n == 0 {
                        return m | n;
                    }

                    // Remove the common power of two.
                    let shift = (m | n).trailing_zeros();

                    // Make both remaining factors odd.
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

                    assert!(x >= y, "xgcd requires x >= y, got x={x}, y={y}");

                    u1 = 1;
                    v2 = 1;
                    u2 = 0;
                    v1 = 0;
                    u3 = x;
                    v3 = y;

                    // `x` and `y` both have their top bit set.
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

                    // `v3` has its second-highest bit set.
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

                        // The top two bits of `v3` are clear, so `v3 << 2`
                        // cannot overflow.
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

                    // The coefficient bound `|u1| < x / 2` guarantees that
                    // its word-width representation has an unambiguous sign.
                    // Choose the equivalent representatives needed for the
                    // returned unsigned form `a * x - b * y = gcd(x, y)`.
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

                    assert!(y > x, "gcdinv requires x < modulus, got x={x}, modulus={y}");

                    v1 = 0;
                    v2 = 1;
                    r = x;
                    x = y;

                    // `x` and `r` both have their top bit set.
                    if ((x & r) as $SignedT) < 0 {
                        d = x - r;
                        t2 = v2;
                        x = r;
                        v2 = coeff_sub(v1, v2);
                        v1 = t2;
                        r = d;
                    }

                    // `r` has its second-highest bit set.
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
                        // The top two bits of `r` are clear, so `r << 2`
                        // cannot overflow.
                        if x < (r << 2) {
                            // The quotient is less than four.
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
                        // Normalize the tracked coefficient into `[0, y)`.
                        v1 = v1.wrapping_add_unsigned(y);
                    }

                    (v1 as Self, x)
                }

                #[inline]
                fn gcdinv_pow_of_2(a: Self, mask: Self) -> Option<Self> {
                    assert!(
                        mask != 0 && (mask & mask.wrapping_add(1)) == 0,
                        "mask must be of the form 2^k - 1 for 1 <= k <= Self::BITS"
                    );
                    if a & 0b1 == 0 {
                        return None;
                    }

                    if mask == Self::MAX {
                        Some(inverse_odd_mod_native(a))
                    } else {
                        Some(inverse_odd_mod_mask(a, mask))
                    }
                }

                #[inline]
                fn gcdinv_native(a: Self) -> Option<Self> {
                    if a & 0b1 == 0 {
                        return None;
                    }

                    Some(inverse_odd_mod_native(a))
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
