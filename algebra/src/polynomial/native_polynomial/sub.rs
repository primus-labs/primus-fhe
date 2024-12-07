use std::ops::{Sub, SubAssign};

use crate::SubOps;

use super::Polynomial;

impl<F> Polynomial<F>
where
    F: SubOps,
{
    /// Performs subtraction operation:`self - rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.iter()
            .zip(rhs)
            .zip(destination)
            .for_each(|((&x, &y), z)| {
                *z = x - y;
            })
    }
}

impl<F: SubOps> SubAssign<Self> for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, r)| *l -= r);
    }
}
impl<F: SubOps> SubAssign<&Self> for Polynomial<F> {
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        self.iter_mut().zip(rhs).for_each(|(l, &r)| *l -= r);
    }
}

impl<F: SubOps> Sub<Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: SubOps> Sub<&Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: &Self) -> Self::Output {
        SubAssign::sub_assign(&mut self, rhs);
        self
    }
}

impl<F: SubOps> Sub<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn sub(self, mut rhs: Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        rhs.iter_mut().zip(self).for_each(|(r, &l)| *r = l - *r);
        rhs
    }
}

impl<F: SubOps> Sub<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn sub(self, rhs: &Polynomial<F>) -> Self::Output {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let polynomial: Vec<F> = self.iter().zip(rhs).map(|(&l, &r)| l - r).collect();
        <Polynomial<F>>::new(polynomial)
    }
}
