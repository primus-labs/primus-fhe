use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::ring::Ring;

use crate::util::Vector;

/// A generic lwe struct type.
#[derive(Clone)]
pub struct LWE<R: Ring> {
    a: Vector<R>,
    b: R,
}

impl<R: Ring> LWE<R> {
    /// Creates a new [`LWE<R>`].
    #[inline]
    pub fn new(a: Vector<R>, b: R) -> Self {
        Self { a, b }
    }

    /// Decrypt the [`LWE<R>`] by the secret `s`.
    ///
    /// Return the encoded message.
    #[inline]
    pub fn decrypt(&self, s: &Vector<R>) -> R {
        self.b - self.a.dot_product(s)
    }
}

impl<R: Ring> Add<Self> for LWE<R> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.add(a1),
            b: b0.add(b1),
        }
    }
}

impl<R: Ring> Add<&Self> for LWE<R> {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.add(a1),
            b: b0.add(b1),
        }
    }
}

impl<R: Ring> Sub<Self> for LWE<R> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.sub(a1),
            b: b0.sub(b1),
        }
    }
}

impl<R: Ring> Sub<&Self> for LWE<R> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.sub(a1),
            b: b0.sub(b1),
        }
    }
}

impl<R: Ring> Mul<Self> for LWE<R> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.mul(a1),
            b: b0.mul(b1),
        }
    }
}

impl<R: Ring> Mul<&Self> for LWE<R> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        Self {
            a: a0.mul(a1),
            b: b0.mul(b1),
        }
    }
}

impl<R: Ring> AddAssign<Self> for LWE<R> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<R: Ring> AddAssign<&Self> for LWE<R> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.add_assign(a1);
        b0.add_assign(b1);
    }
}

impl<R: Ring> SubAssign<Self> for LWE<R> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<R: Ring> SubAssign<&Self> for LWE<R> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.sub_assign(a1);
        b0.sub_assign(b1);
    }
}

impl<R: Ring> MulAssign<Self> for LWE<R> {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}

impl<R: Ring> MulAssign<&Self> for LWE<R> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        let Self { a: a0, b: b0 } = self;
        let Self { a: a1, b: b1 } = rhs;
        a0.mul_assign(a1);
        b0.mul_assign(b1);
    }
}
