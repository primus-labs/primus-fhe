use std::ops::{Mul, MulAssign};

use crate::{transformation::AbstractNTT, AddOps, MulOps, NTTField, NTTPolynomial, SubOps};

use super::Polynomial;

impl<F: MulOps> Polynomial<F> {
    /// Multiply `self` with the a scalar.
    #[inline]
    pub fn mul_scalar(&self, scalar: F) -> Self {
        Self::new(self.iter().map(|&v| v * scalar).collect())
    }

    /// Multiply `self` with the a scalar inplace.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: F) {
        self.iter_mut().for_each(|v| *v *= scalar)
    }
}

impl<F: MulOps + AddOps> Polynomial<F> {
    /// Multiply `self` with the a scalar inplace.
    #[inline]
    pub fn add_mul_scalar_assign(&mut self, rhs: &Self, scalar: F) {
        self.iter_mut()
            .zip(rhs.iter())
            .for_each(|(r, &v)| *r += v * scalar)
    }
}

impl<F: AddOps + SubOps + MulOps> Polynomial<F> {
    ///
    pub fn normal_mul(&self, rhs: &Polynomial<F>) -> Polynomial<F> {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        let coeff_count = self.coeff_count();

        let mut destination = vec![F::ZERO; coeff_count];
        let poly1: &[F] = self.as_ref();
        let poly2: &[F] = rhs.as_ref();

        for i in 0..coeff_count {
            for j in 0..=i {
                destination[i] += poly1[j] * poly2[i - j];
            }
        }

        // mod (x^n + 1)
        for i in coeff_count..coeff_count * 2 - 1 {
            let k = i - coeff_count;
            for j in i - coeff_count + 1..coeff_count {
                destination[k] -= poly1[j] * poly2[i - j]
            }
        }

        Polynomial::new(destination)
    }

    ///
    pub fn normal_mul_inplace(&self, rhs: &Polynomial<F>, destination: &mut Polynomial<F>) {
        debug_assert_eq!(self.coeff_count(), rhs.coeff_count());
        debug_assert_eq!(self.coeff_count(), destination.coeff_count());
        let coeff_count = self.coeff_count();

        let poly1: &[F] = self.as_ref();
        let poly2: &[F] = rhs.as_ref();

        for i in 0..coeff_count {
            for j in 0..=i {
                destination[i] += poly1[j] * poly2[i - j];
            }
        }

        // mod (x^n + 1)
        for i in coeff_count..coeff_count * 2 - 1 {
            let k = i - coeff_count;
            for j in i - coeff_count + 1..coeff_count {
                destination[k] -= poly1[j] * poly2[i - j]
            }
        }
    }
}

impl<F: NTTField> MulAssign<Self> for Polynomial<F> {
    fn mul_assign(&mut self, rhs: Self) {
        let coeff_count = self.coeff_count();
        debug_assert_eq!(coeff_count, rhs.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());

        let log_n = coeff_count.trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let lhs = self.as_mut_slice();
        let rhs = ntt_table.transform_inplace(rhs);
        ntt_table.transform_slice(lhs);
        ntt_mul_assign_fast(lhs, &rhs);
        ntt_table.inverse_transform_slice(lhs);
    }
}

impl<F: NTTField> MulAssign<&Self> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        MulAssign::mul_assign(self, rhs.clone());
    }
}

impl<F: NTTField> Mul<Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<&Self> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &Self) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, mut rhs: Polynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut rhs, self.clone());
        rhs
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: &Polynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs.clone())
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for Polynomial<F> {
    type Output = Self;

    #[inline]
    fn mul(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        MulAssign::mul_assign(&mut self, rhs);
        self
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs)
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for &Polynomial<F> {
    type Output = Polynomial<F>;

    #[inline]
    fn mul(self, rhs: &NTTPolynomial<F>) -> Self::Output {
        Mul::mul(self.clone(), rhs)
    }
}

impl<F: NTTField> MulAssign<NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: NTTPolynomial<F>) {
        let coeff_count = self.coeff_count();
        debug_assert_eq!(coeff_count, rhs.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());

        let log_n = coeff_count.trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let lhs = self.as_mut_slice();
        ntt_table.transform_slice(lhs);
        ntt_mul_assign_fast(lhs, &rhs);
        ntt_table.inverse_transform_slice(lhs);
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for Polynomial<F> {
    #[inline]
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        let coeff_count = self.coeff_count();
        debug_assert_eq!(coeff_count, rhs.coeff_count());
        debug_assert!(coeff_count.is_power_of_two());

        let log_n = coeff_count.trailing_zeros();
        let ntt_table = F::get_ntt_table(log_n).unwrap();

        let lhs = self.as_mut_slice();
        ntt_table.transform_slice(lhs);
        ntt_mul_assign_fast(lhs, rhs);
        ntt_table.inverse_transform_slice(lhs);
    }
}

/// Performs entry-wise fast mul operation.
///
/// The result coefficients may be in [0, 2*modulus) for some case,
/// and fall back to [0, modulus) for normal case.
#[inline]
fn ntt_mul_assign_fast<F: NTTField>(lhs: &mut [F], rhs: &NTTPolynomial<F>) {
    lhs.iter_mut()
        .zip(rhs)
        .for_each(|(l, &r)| l.mul_assign_fast(r));
}
