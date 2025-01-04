//! This implementation refers to the following codebases.
//! <https://flintlib.org/doc/ulong_extras.html#c.n_xgcd>
//! <https://flintlib.org/doc/ulong_extras.html#c.n_gcdinv>

/// Greatest common divisor and Bézout coefficients
pub trait Xgcd: Sized {
    /// Signed type for extended GCD.
    type SignedT;

    /// Calculates the Greatest Common Divisor (GCD) of the number and `other`. The
    /// result is always non-negative.
    fn gcd(self, other: Self) -> Self;

    /// Check whether two numbers are coprime.
    fn coprime(self, other: Self) -> bool;

    /// Check whether two numbers are not coprime.
    fn not_coprime(self, other: Self) -> bool;

    /// Returns the greatest common divisor `g` of `x` and `y` and unsigned
    /// values `a` and `b` such that `a x - b y = g`. We require `x ≥ y`.
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
    /// But at the previous step in the backsubstitution we would have had
    /// `1 = s r - c d` with `s < r/2` and `c < r/2`.
    ///
    /// Then `s + t q < r/2 + y_n / 2 q = (r + q y_n)/2 = x_n / 2`.
    fn xgcd(x: Self, y: Self) -> (Self, Self, Self);

    /// Returns the greatest common divisor `g` of `x` and `y` and computes
    /// `a` such that `0 ≤ a < y` and `a x = gcd(x, y) mod y`, when
    /// this is defined. We require `x < y`.
    ///
    /// When `y = 1` the greatest common divisor is set to `1` and `a` is
    /// set to `0`.
    ///
    /// This is merely an adaption of the extended Euclidean algorithm
    /// computing just one cofactor and reducing it modulo `y`.
    fn gcdinv(x: Self, y: Self) -> (Self, Self);
}

macro_rules! impl_extended_gcd {
    (impl Xgcd for $SelfT:ty; SignedType: $SignedT:ty) => {
        impl Xgcd for $SelfT {
            type SignedT = $SignedT;

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

            #[inline(always)]
            fn coprime(self, other: Self) -> bool {
                self.gcd(other) <= 1
            }

            #[inline(always)]
            fn not_coprime(self, other: Self) -> bool {
                self.gcd(other) > 1
            }

            #[inline]
            fn xgcd(x: Self, y: Self) -> (Self, Self, Self) {
                let mut u1: Self::SignedT;
                let mut u2: Self::SignedT;
                let mut v1: Self::SignedT;
                let mut v2: Self::SignedT;
                let mut t1: Self::SignedT;
                let mut t2: Self::SignedT;

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
                if ((x & y) as Self::SignedT) < 0 {
                    d = u3 - v3;
                    t2 = v2;
                    t1 = u2;
                    u2 = u1 - u2;
                    u1 = t1;
                    u3 = v3;
                    v2 = v1 - v2;
                    v1 = t2;
                    v3 = d;
                }

                // second value has second msb set
                while ((v3 << 1) as Self::SignedT) < 0 {
                    d = u3 - v3;
                    if d < v3 {
                        // quot = 1
                        t2 = v2;
                        t1 = u2;
                        u2 = u1 - u2;
                        u1 = t1;
                        u3 = v3;
                        v2 = v1 - v2;
                        v1 = t2;
                        v3 = d;
                    } else if d < (v3 << 1) {
                        // quot = 2
                        t1 = u2;
                        u2 = u1 - (u2 << 1);
                        u1 = t1;
                        u3 = v3;
                        t2 = v2;
                        v2 = v1 - (v2 << 1);
                        v1 = t2;
                        v3 = d - u3;
                    } else {
                        // quot = 3
                        t1 = u2;
                        u2 = u1 - 3 * u2;
                        u1 = t1;
                        u3 = v3;
                        t2 = v2;
                        v2 = v1 - 3 * v2;
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
                            u2 = u1 - u2;
                            u1 = t1;
                            u3 = v3;
                            v2 = v1 - v2;
                            v1 = t2;
                            v3 = d;
                        } else if d < (v3 << 1) {
                            // quot = 2
                            t1 = u2;
                            u2 = u1 - (u2 << 1);
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = v1 - (v2 << 1);
                            v1 = t2;
                            v3 = d - u3;
                        } else {
                            // quot = 3
                            t1 = u2;
                            u2 = u1 - 3 * u2;
                            u1 = t1;
                            u3 = v3;
                            t2 = v2;
                            v2 = v1 - 3 * v2;
                            v1 = t2;
                            v3 = d - (u3 << 1);
                        }
                    } else {
                        quot = u3 / v3;
                        rem = u3 - v3 * quot;
                        t1 = u2;
                        u2 = u1 - (quot as Self::SignedT) * u2;
                        u1 = t1;
                        u3 = v3;
                        t2 = v2;
                        v2 = v1 - (quot as Self::SignedT) * v2;
                        v1 = t2;
                        v3 = rem;
                    }
                }

                /* Remarkably, |u1| < x/2, thus comparison with 0 is valid */
                if u1 <= 0 {
                    u1 = u1.wrapping_add_unsigned(y);
                    v1 = v1.wrapping_sub_unsigned(x);
                }

                (u1 as Self, -v1 as Self, u3)
            }

            #[inline]
            fn gcdinv(mut x: Self, y: Self) -> (Self, Self) {
                let mut v1: Self::SignedT;
                let mut v2: Self::SignedT;
                let mut t2: Self::SignedT;

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
                if ((x & r) as Self::SignedT) < 0 {
                    d = x - r;
                    t2 = v2;
                    x = r;
                    v2 = v1 - v2;
                    v1 = t2;
                    r = d;
                }

                // second value has second msb set
                while ((r << 1) as Self::SignedT) < 0 {
                    d = x - r;
                    if (d < r) {
                        // quot = 1
                        t2 = v2;
                        x = r;
                        v2 = v1 - v2;
                        v1 = t2;
                        r = d;
                    } else if (d < (r << 1)) {
                        // quot = 2
                        x = r;
                        t2 = v2;
                        v2 = v1 - (v2 << 1);
                        v1 = t2;
                        r = d - x;
                    } else {
                        // quot = 3
                        x = r;
                        t2 = v2;
                        v2 = v1 - 3 * v2;
                        v1 = t2;
                        r = d - (x << 1);
                    }
                }

                while r > 0 {
                    // overflow not possible due to top 2 bits of r not being set
                    if x < (r << 2) {
                        // if quot < 4
                        d = x - r;
                        if (d < r) {
                            // quot = 1
                            t2 = v2;
                            x = r;
                            v2 = v1 - v2;
                            v1 = t2;
                            r = d;
                        } else if d < (r << 1) {
                            // quot = 2
                            x = r;
                            t2 = v2;
                            v2 = v1 - (v2 << 1);
                            v1 = t2;
                            r = d - x;
                        } else {
                            // quot = 3
                            x = r;
                            t2 = v2;
                            v2 = v1 - 3 * v2;
                            v1 = t2;
                            r = d - (x << 1);
                        }
                    } else {
                        quot = x / r;
                        rem = x - r * quot;
                        x = r;
                        t2 = v2;
                        v2 = v1 - (quot as Self::SignedT) * v2;
                        v1 = t2;
                        r = rem;
                    }
                }

                if v1 < 0 {
                    v1 = v1.wrapping_add_unsigned(y);
                }

                (v1 as Self, x)
            }
        }
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
    use rand::prelude::*;

    use super::*;

    type ValueT = u64;
    type WideT = u128;

    #[test]
    fn test_xgcd() {
        let mut rng = thread_rng();

        let x = rng.gen_range(0..ValueT::MAX >> 1);
        let y = rng.gen_range(0..=x);

        let (a, b, d) = ValueT::xgcd(x, y);
        assert_eq!(
            a as WideT * x as WideT - b as WideT * y as WideT,
            d as WideT
        );
    }

    #[test]
    fn test_gcdinv() {
        let mut rng = thread_rng();

        let y = rng.gen_range(0..ValueT::MAX >> 1);
        let x = rng.gen_range(0..y);

        let (a, d) = ValueT::gcdinv(x, y);
        assert_eq!((a as WideT * x as WideT) % y as WideT, d as WideT);
    }
}
