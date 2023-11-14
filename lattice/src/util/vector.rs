use std::ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Sub, SubAssign};

use algebra::ring::Ring;

/// A generic vector type that implements basic mathematical operations.
#[derive(Debug, Clone, PartialEq)]
pub struct Vector<Element: Ring>(Vec<Element>);

impl<Element: Ring> Deref for Vector<Element> {
    type Target = Vec<Element>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Element: Ring> DerefMut for Vector<Element> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Element: Ring> From<Vec<Element>> for Vector<Element> {
    #[inline]
    fn from(values: Vec<Element>) -> Self {
        Self(values)
    }
}

impl<Element: Ring> Vector<Element> {
    /// Creates a new [`Vector<Element>`].
    #[inline]
    pub fn new(values: Vec<Element>) -> Self {
        Self(values)
    }

    /// Perform dot product of two vectors of ring.
    #[inline]
    pub fn dot_product(&self, rhs: &Vector<Element>) -> Element {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .fold(Element::zero(), |acc, (a, b)| acc + *a * b)
    }
}

impl<Element: Ring> AddAssign<Vector<Element>> for Vector<Element> {
    #[inline]
    fn add_assign(&mut self, rhs: Vector<Element>) {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(a, b)| a.add_assign(b));
    }
}

impl<Element: Ring> AddAssign<&Vector<Element>> for Vector<Element> {
    #[inline]
    fn add_assign(&mut self, rhs: &Vector<Element>) {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .for_each(|(a, b)| a.add_assign(b));
    }
}

impl<Element: Ring> Add<Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn add(mut self, rhs: Vector<Element>) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<Element: Ring> Add<&Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn add(mut self, rhs: &Vector<Element>) -> Self::Output {
        AddAssign::add_assign(&mut self, rhs);
        self
    }
}

impl<Element: Ring> SubAssign<Vector<Element>> for Vector<Element> {
    #[inline]
    fn sub_assign(&mut self, rhs: Vector<Element>) {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(a, b)| a.sub_assign(b));
    }
}

impl<Element: Ring> SubAssign<&Vector<Element>> for Vector<Element> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Vector<Element>) {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .for_each(|(a, b)| a.sub_assign(b));
    }
}

impl<Element: Ring> Sub<Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn sub(mut self, rhs: Vector<Element>) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<Element: Ring> Sub<&Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn sub(mut self, rhs: &Vector<Element>) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<Element: Ring> MulAssign<Vector<Element>> for Vector<Element> {
    #[inline]
    fn mul_assign(&mut self, rhs: Vector<Element>) {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(a, b)| a.mul_assign(b));
    }
}

impl<Element: Ring> MulAssign<&Vector<Element>> for Vector<Element> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Vector<Element>) {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .for_each(|(a, b)| a.mul_assign(b));
    }
}

impl<Element: Ring> Mul<Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn mul(mut self, rhs: Vector<Element>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<Element: Ring> Mul<&Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn mul(mut self, rhs: &Vector<Element>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

#[cfg(test)]
mod tests {
    use algebra::field::{Field, Fp32};

    use super::*;

    #[test]
    fn test_vector() {
        let p: u32 = Fp32::modulus();

        let a = Vector::new(vec![Fp32::new(1), Fp32::new(2), Fp32::new(4), Fp32::new(8)]);
        let b = Vector::new(vec![
            Fp32::new(16),
            Fp32::new(32),
            Fp32::new(64),
            Fp32::new(128),
        ]);

        let c = Vector::new(vec![
            Fp32::new(17),
            Fp32::new(34),
            Fp32::new(68),
            Fp32::new(136),
        ]);
        assert_eq!(a.clone() + &b, c);

        let c = Vector::new(vec![
            Fp32::new(p - 16 + 1),
            Fp32::new(p - 32 + 2),
            Fp32::new(p - 64 + 4),
            Fp32::new(p - 128 + 8),
        ]);
        assert_eq!(a.clone() - &b, c);

        let c = Vector::new(vec![
            Fp32::new(16),
            Fp32::new(64),
            Fp32::new(256),
            Fp32::new(1024),
        ]);
        assert_eq!(a.clone() * &b, c);

        assert_eq!(a.dot_product(&b), Fp32::new(16 + 2 * 32 + 4 * 64 + 8 * 128));
    }
}
