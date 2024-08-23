use crate::{AbstractExtensionField, Field};
use std::ops::{Add, Mul, Sub};

/// Unified Field
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum UF<F: Field, EF: AbstractExtensionField<F>> {
    /// Base Field Element
    BaseField(F),
    /// Extension Field Element
    ExtensionField(EF),
}

impl<F: Field, EF: AbstractExtensionField<F>> UF<F, EF> {
    /// Return one
    pub fn one() -> UF<F, EF> {
        UF::BaseField(F::one())
    }
    /// Return zero
    pub fn zero() -> UF<F, EF> {
        UF::BaseField(F::zero())
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Mul<Self> for UF<F, EF> {
    type Output = EF;
    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (UF::BaseField(l), UF::BaseField(r)) => EF::from_base(l * r),
            (UF::BaseField(l), UF::ExtensionField(r)) => r * l,
            (UF::ExtensionField(l), UF::BaseField(r)) => l * r,
            (UF::ExtensionField(l), UF::ExtensionField(r)) => l * r,
        }
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Add<Self> for UF<F, EF> {
    type Output = EF;
    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (UF::BaseField(l), UF::BaseField(r)) => EF::from_base(l + r),
            (UF::BaseField(l), UF::ExtensionField(r)) => r + l,
            (UF::ExtensionField(l), UF::BaseField(r)) => l + r,
            (UF::ExtensionField(l), UF::ExtensionField(r)) => l + r,
        }
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Sub<Self> for UF<F, EF> {
    type Output = EF;
    fn sub(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (UF::BaseField(l), UF::BaseField(r)) => EF::from_base(l - r),
            (UF::BaseField(l), UF::ExtensionField(r)) => EF::from_base(l) - r,
            (UF::ExtensionField(l), UF::BaseField(r)) => l - r,
            (UF::ExtensionField(l), UF::ExtensionField(r)) => l - r,
        }
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Mul<EF> for UF<F, EF> {
    type Output = EF;
    fn mul(self, r: EF) -> Self::Output {
        match self {
            UF::BaseField(l) => r * l,
            UF::ExtensionField(l) => l * r,
        }
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> Add<EF> for UF<F, EF> {
    type Output = EF;
    fn add(self, r: EF) -> Self::Output {
        match self {
            UF::BaseField(l) => r + l,
            UF::ExtensionField(l) => l + r,
        }
    }
}
