use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

use algebra::field::NTTField;
use algebra::polynomial::{NTTPolynomial, Polynomial};

mod coef;
mod gadget;
mod ntt;

pub use {coef::RlweModeCoef, gadget::GadgetRLWE, ntt::RlweModeNTT};

/// A generic RLWE struct type, which has two inner type.
///
/// One is coefficients mode, all data is the polynomial coefficients.
/// The other is ntt mode, the data is in the vector type.
#[derive(Clone)]
pub enum RLWE<F: NTTField> {
    /// A RLWE with coefficients
    CoefMode(RlweModeCoef<F>),
    /// A RLWE with values
    NttMode(RlweModeNTT<F>),
}

impl<F: NTTField> RLWE<F> {
    #[inline]
    pub(crate) fn zero_with_coeff_count(coeff_count: usize) -> Self {
        let a = NTTPolynomial::zero_with_coeff_count(coeff_count);
        let b = NTTPolynomial::zero_with_coeff_count(coeff_count);
        Self::NttMode(RlweModeNTT { a, b })
    }

    /// Creates a new [`RLWE<F>`] of coefficients mode.
    #[inline]
    pub fn from_coef_mode(a: Polynomial<F>, b: Polynomial<F>) -> Self {
        Self::CoefMode(RlweModeCoef { a, b })
    }

    /// Creates a new [`RLWE<F>`] of ntt mode.
    #[inline]
    pub fn from_ntt_mode(a: NTTPolynomial<F>, b: NTTPolynomial<F>) -> Self {
        Self::NttMode(RlweModeNTT { a, b })
    }
}

macro_rules! binary_op {
    ($left:ident, $right:ident, $op:tt) => {
        // prefer ntt mode
        match ($left, $right) {
            (RLWE::NttMode(c0), RLWE::NttMode(c1)) => RLWE::NttMode(c0 $op c1),
            (RLWE::CoefMode(c0), RLWE::CoefMode(c1)) => RLWE::CoefMode(c0 $op c1),
            (RLWE::CoefMode(c0), RLWE::NttMode(c1)) => {
                let c0: RlweModeNTT<F> = c0.into();
                RLWE::NttMode(c0 $op c1)
            }
            (RLWE::NttMode(c0), RLWE::CoefMode(c1)) => {
                let c1: RlweModeNTT<F> = c1.into();
                RLWE::NttMode(c0 $op c1)
            }
        }
    };
}

macro_rules! binary_mul {
    ($left:ident, $right:ident) => {
        match ($left, $right) {
            // prefer ntt mode
            (RLWE::NttMode(c0), RLWE::NttMode(c1)) => RLWE::NttMode(c0 * c1),
            (RLWE::CoefMode(c0), RLWE::CoefMode(c1)) => {
                let c0: RlweModeNTT<F> = c0.into();
                let c1: RlweModeNTT<F> = c1.into();
                RLWE::NttMode(c0 * c1)
            }
            (RLWE::CoefMode(c0), RLWE::NttMode(c1)) => {
                let c0: RlweModeNTT<F> = c0.into();
                RLWE::NttMode(c0 * c1)
            }
            (RLWE::NttMode(c0), RLWE::CoefMode(c1)) => {
                let c1: RlweModeNTT<F> = c1.into();
                RLWE::NttMode(c0 * c1)
            }
        }
    };
}

macro_rules! assign_op {
    ($left:ident, $right:ident, $assign_method:ident) => {
        match ($left, $right) {
            (RLWE::NttMode(c0), RLWE::NttMode(c1)) => c0.$assign_method(c1),
            (RLWE::CoefMode(c0), RLWE::CoefMode(c1)) => c0.$assign_method(c1),
            (RLWE::CoefMode(c0), RLWE::NttMode(c1)) => {
                let c1: RlweModeCoef<F> = c1.into();
                c0.$assign_method(c1)
            }
            (RLWE::NttMode(c0), RLWE::CoefMode(c1)) => {
                let c1: RlweModeNTT<F> = c1.into();
                c0.$assign_method(c1)
            }
        }
    };
}

impl<F: NTTField> Add<Self> for RLWE<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        binary_op!(self, rhs, +)
    }
}

impl<F: NTTField> Add<&Self> for RLWE<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        binary_op!(self, rhs, +)
    }
}

impl<F: NTTField> Sub<Self> for RLWE<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        binary_op!(self, rhs, -)
    }
}

impl<F: NTTField> Sub<&Self> for RLWE<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        binary_op!(self, rhs, -)
    }
}

impl<F: NTTField> Mul<Self> for RLWE<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        binary_mul!(self, rhs)
    }
}

impl<F: NTTField> Mul<&Self> for RLWE<F> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        binary_mul!(self, rhs)
    }
}

impl<F: NTTField> AddAssign<Self> for RLWE<F> {
    fn add_assign(&mut self, rhs: Self) {
        assign_op!(self, rhs, add_assign)
    }
}

impl<F: NTTField> AddAssign<&Self> for RLWE<F> {
    fn add_assign(&mut self, rhs: &Self) {
        assign_op!(self, rhs, add_assign)
    }
}

impl<F: NTTField> SubAssign<Self> for RLWE<F> {
    fn sub_assign(&mut self, rhs: Self) {
        assign_op!(self, rhs, sub_assign)
    }
}

impl<F: NTTField> SubAssign<&Self> for RLWE<F> {
    fn sub_assign(&mut self, rhs: &Self) {
        assign_op!(self, rhs, sub_assign)
    }
}

impl<F: NTTField> MulAssign<Self> for RLWE<F> {
    fn mul_assign(&mut self, rhs: Self) {
        assign_op!(self, rhs, mul_assign)
    }
}

impl<F: NTTField> MulAssign<&Self> for RLWE<F> {
    fn mul_assign(&mut self, rhs: &Self) {
        assign_op!(self, rhs, mul_assign)
    }
}

macro_rules! op_poly {
    ($left:ident, $right:ident, $assign_method:ident) => {
        match $left {
            RLWE::CoefMode(ref mut c0) => c0.$assign_method($right),
            RLWE::NttMode(ref mut c0) => c0.$assign_method($right),
        }
    };
}

impl<F: NTTField> Add<Polynomial<F>> for RLWE<F> {
    type Output = Self;

    fn add(mut self, rhs: Polynomial<F>) -> Self::Output {
        op_poly!(self, rhs, add_assign);
        self
    }
}

impl<F: NTTField> Add<&Polynomial<F>> for RLWE<F> {
    type Output = Self;

    fn add(mut self, rhs: &Polynomial<F>) -> Self::Output {
        op_poly!(self, rhs, add_assign);
        self
    }
}

impl<F: NTTField> Add<NTTPolynomial<F>> for RLWE<F> {
    type Output = Self;

    fn add(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        op_poly!(self, rhs, add_assign);
        self
    }
}

impl<F: NTTField> Add<&NTTPolynomial<F>> for RLWE<F> {
    type Output = Self;

    fn add(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        op_poly!(self, rhs, add_assign);
        self
    }
}

impl<F: NTTField> Sub<Polynomial<F>> for RLWE<F> {
    type Output = Self;

    fn sub(mut self, rhs: Polynomial<F>) -> Self::Output {
        op_poly!(self, rhs, sub_assign);
        self
    }
}

impl<F: NTTField> Sub<&Polynomial<F>> for RLWE<F> {
    type Output = Self;

    fn sub(mut self, rhs: &Polynomial<F>) -> Self::Output {
        op_poly!(self, rhs, sub_assign);
        self
    }
}

impl<F: NTTField> Sub<NTTPolynomial<F>> for RLWE<F> {
    type Output = Self;

    fn sub(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        op_poly!(self, rhs, sub_assign);
        self
    }
}

impl<F: NTTField> Sub<&NTTPolynomial<F>> for RLWE<F> {
    type Output = Self;

    fn sub(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        op_poly!(self, rhs, sub_assign);
        self
    }
}

impl<F: NTTField> Mul<Polynomial<F>> for RLWE<F> {
    type Output = RLWE<F>;

    fn mul(mut self, rhs: Polynomial<F>) -> Self::Output {
        op_poly!(self, rhs, mul_assign);
        self
    }
}

impl<F: NTTField> Mul<&Polynomial<F>> for RLWE<F> {
    type Output = RLWE<F>;

    fn mul(mut self, rhs: &Polynomial<F>) -> Self::Output {
        op_poly!(self, rhs, mul_assign);
        self
    }
}

impl<F: NTTField> Mul<NTTPolynomial<F>> for RLWE<F> {
    type Output = RLWE<F>;

    fn mul(mut self, rhs: NTTPolynomial<F>) -> Self::Output {
        op_poly!(self, rhs, mul_assign);
        self
    }
}

impl<F: NTTField> Mul<&NTTPolynomial<F>> for RLWE<F> {
    type Output = RLWE<F>;

    fn mul(mut self, rhs: &NTTPolynomial<F>) -> Self::Output {
        op_poly!(self, rhs, mul_assign);
        self
    }
}

impl<F: NTTField> AddAssign<Polynomial<F>> for RLWE<F> {
    fn add_assign(&mut self, rhs: Polynomial<F>) {
        op_poly!(self, rhs, add_assign);
    }
}

impl<F: NTTField> AddAssign<&Polynomial<F>> for RLWE<F> {
    fn add_assign(&mut self, rhs: &Polynomial<F>) {
        op_poly!(self, rhs, add_assign);
    }
}

impl<F: NTTField> AddAssign<NTTPolynomial<F>> for RLWE<F> {
    fn add_assign(&mut self, rhs: NTTPolynomial<F>) {
        op_poly!(self, rhs, add_assign);
    }
}

impl<F: NTTField> AddAssign<&NTTPolynomial<F>> for RLWE<F> {
    fn add_assign(&mut self, rhs: &NTTPolynomial<F>) {
        op_poly!(self, rhs, add_assign);
    }
}

impl<F: NTTField> SubAssign<Polynomial<F>> for RLWE<F> {
    fn sub_assign(&mut self, rhs: Polynomial<F>) {
        op_poly!(self, rhs, sub_assign);
    }
}

impl<F: NTTField> SubAssign<&Polynomial<F>> for RLWE<F> {
    fn sub_assign(&mut self, rhs: &Polynomial<F>) {
        op_poly!(self, rhs, sub_assign);
    }
}

impl<F: NTTField> SubAssign<NTTPolynomial<F>> for RLWE<F> {
    fn sub_assign(&mut self, rhs: NTTPolynomial<F>) {
        op_poly!(self, rhs, sub_assign);
    }
}

impl<F: NTTField> SubAssign<&NTTPolynomial<F>> for RLWE<F> {
    fn sub_assign(&mut self, rhs: &NTTPolynomial<F>) {
        op_poly!(self, rhs, sub_assign);
    }
}

impl<F: NTTField> MulAssign<NTTPolynomial<F>> for RLWE<F> {
    fn mul_assign(&mut self, rhs: NTTPolynomial<F>) {
        match self {
            RLWE::CoefMode(c) => {
                *self = RLWE::NttMode(RlweModeNTT {
                    a: &rhs * c.a(),
                    b: rhs * c.b(),
                });
            }
            RLWE::NttMode(c) => c.mul_assign(rhs),
        }
    }
}

impl<F: NTTField> MulAssign<&NTTPolynomial<F>> for RLWE<F> {
    fn mul_assign(&mut self, rhs: &NTTPolynomial<F>) {
        match self {
            RLWE::CoefMode(c) => {
                *self = RLWE::NttMode(RlweModeNTT {
                    a: rhs * c.a(),
                    b: rhs * c.b(),
                });
            }
            RLWE::NttMode(c) => c.mul_assign(rhs),
        }
    }
}
