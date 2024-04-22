/// Greatest common divisor and Bézout coefficients
pub trait ExtendedGCD {
    /// Signed type for extended GCD.
    type SignedT;

    /// Calculates the Greatest Common Divisor (GCD) of the number and `other`. The
    /// result is always non-negative.
    fn gcd(self, other: Self) -> Self;

    /// Check whether two numbers are coprime.
    fn coprime(self, other: Self) -> bool;

    /// Check whether two numbers are not coprime.
    fn not_coprime(self, other: Self) -> bool;

    /// Greatest common divisor and Bézout coefficients.
    ///
    /// INPUT: two positive integers `x` and `y`.
    ///
    /// OUTPUT: integers `a`, `b`, and `v` such that `ax + by = v`, where `v = gcd(x, y)`.
    fn extended_gcd(x: Self, y: Self) -> (Self::SignedT, Self::SignedT, Self);
}

macro_rules! impl_extended_gcd {
    (impl ExtendedGCD for $SelfT:ty; SignedType: $SignedT:ty) => {
        impl ExtendedGCD for $SelfT {
            type SignedT = $SignedT;

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
            fn coprime(self, other: Self) -> bool {
                self.gcd(other) <= 1
            }

            #[inline]
            fn not_coprime(self, other: Self) -> bool {
                self.gcd(other) > 1
            }

            fn extended_gcd(mut x: Self, mut y: Self) -> (Self::SignedT, Self::SignedT, Self) {
                if x == 0 || y == 0 {
                    return (0, 0, 0);
                }
                let mut g = 1;

                let shift = (x | y).trailing_zeros();
                x >>= shift;
                y >>= shift;
                g <<= shift;

                // ax + by = u
                // cx + dy = v
                let mut u: Self = x;
                let mut v: Self = y;
                let mut a: Self::SignedT = 1;
                let mut b: Self::SignedT = 0;
                let mut c: Self::SignedT = 0;
                let mut d: Self::SignedT = 1;

                loop {
                    while u % 2 == 0 {
                        u >>= 1;
                        if a % 2 == 0 && b % 2 == 0 {
                            a >>= 1;
                            b >>= 1;
                        } else if b > x as Self::SignedT {
                            a = (a + y as Self::SignedT) >> 1;
                            b = (b - x as Self::SignedT) >> 1;
                        } else {
                            a = (a - y as Self::SignedT) >> 1;
                            b = (b + x as Self::SignedT) >> 1;
                        }
                    }

                    while v % 2 == 0 {
                        v >>= 1;
                        if c % 2 == 0 && d % 2 == 0 {
                            c >>= 1;
                            d >>= 1;
                        } else if d > x as Self::SignedT {
                            c = (c + y as Self::SignedT) >> 1;
                            d = (d - x as Self::SignedT) >> 1;
                        } else {
                            c = (c - y as Self::SignedT) >> 1;
                            d = (d + x as Self::SignedT) >> 1;
                        }
                    }

                    if u >= v {
                        u -= v;
                        a -= c;
                        b -= d;
                    } else {
                        v -= u;
                        c -= a;
                        d -= b;
                    }

                    if u == 0 {
                        return (c, d, g * v);
                    }
                }
            }
        }
    };
}

impl_extended_gcd!(impl ExtendedGCD for u8; SignedType: i8);
impl_extended_gcd!(impl ExtendedGCD for u16; SignedType: i16);
impl_extended_gcd!(impl ExtendedGCD for u32; SignedType: i32);
impl_extended_gcd!(impl ExtendedGCD for u64; SignedType: i64);

#[cfg(test)]
mod tests {
    use rand::prelude::*;

    use super::*;

    #[test]
    fn test_extended_gcd() {
        let mut rng = thread_rng();

        let x = rng.gen_range(0..=(u64::MAX >> 2));
        let y = rng.gen_range(0..=(u64::MAX >> 2));

        let (a, b, d) = u64::extended_gcd(x, y);

        assert_eq!(a as i128 * x as i128 + b as i128 * y as i128, d as i128);
        // println!("{a}⨉{x}+{b}⨉{y}={d}");
    }
}
