use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::ring::Ring;

#[derive(Clone)]
pub struct Vector<Element: Ring>(Vec<Element>);

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

impl<Element: Ring> Add<Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn add(mut self, rhs: Vector<Element>) -> Self::Output {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(a, b)| a.add_assign(b));
        self
    }
}

impl<Element: Ring> Add<&Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn add(mut self, rhs: &Vector<Element>) -> Self::Output {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .for_each(|(a, b)| a.add_assign(b));
        self
    }
}

impl<Element: Ring> Sub<Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn sub(mut self, rhs: Vector<Element>) -> Self::Output {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(a, b)| a.sub_assign(b));
        self
    }
}

impl<Element: Ring> Sub<&Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn sub(mut self, rhs: &Vector<Element>) -> Self::Output {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .for_each(|(a, b)| a.sub_assign(b));
        self
    }
}

impl<Element: Ring> Mul<Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn mul(mut self, rhs: Vector<Element>) -> Self::Output {
        self.0
            .iter_mut()
            .zip(rhs.0)
            .for_each(|(a, b)| a.mul_assign(b));
        self
    }
}

impl<Element: Ring> Mul<&Vector<Element>> for Vector<Element> {
    type Output = Vector<Element>;

    #[inline]
    fn mul(mut self, rhs: &Vector<Element>) -> Self::Output {
        self.0
            .iter_mut()
            .zip(rhs.0.iter())
            .for_each(|(a, b)| a.mul_assign(b));
        self
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
