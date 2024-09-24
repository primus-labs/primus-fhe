mod binomial_extension;
mod helper;
mod packed;

pub use binomial_extension::*;
pub use helper::*;
pub use packed::*;

use crate::Field;
use core::iter;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// Abstract Extension Field.
pub trait AbstractExtensionField<Base: Field>:
    Field
    + From<Base>
    + Add<Base, Output = Self>
    + Sub<Base, Output = Self>
    + Mul<Base, Output = Self>
    + AddAssign<Base>
    + SubAssign<Base>
    + MulAssign<Base>
{
    /// Extension degree
    const D: usize;

    /// Converts from base field.
    fn from_base(b: Base) -> Self;

    /// Suppose this field extension is represented by the quotient
    /// ring `B[X]/f(X)` where `B` is `Base` and `f` is an irreducible
    /// polynomial of degree `D`. This function takes a slice `bs` of
    /// length at most `D`, and constructs the field element
    /// `∑ᵢ bs[i] * Xⁱ`.
    ///
    /// NB: The value produced by this function fundamentally depends
    /// on the choice of irreducible polynomial f. Care must be taken
    /// to ensure portability if these values might ever be passed to
    /// (or rederived within) another compilation environment where a
    /// different `f` might have been used.
    fn from_base_slice(bs: &[Base]) -> Self;

    /// Similar to `core:array::from_fn`, with the same caveats as
    /// `from_base_slice`.
    fn from_base_fn<F: FnMut(usize) -> Base>(f: F) -> Self;

    /// Suppose this field extension is represented by the quotient
    /// ring `B[X]/f(X)` where `B` is `Base` and `f` is an irreducible
    /// polynomial of degree `D`. This function takes a field element
    /// `∑ᵢ bs[i] * Xⁱ` and returns the coefficients as a slice
    /// `bs` of length at most `D` containing, from lowest degree to
    /// highest.
    ///
    /// NB: The value produced by this function fundamentally depends
    /// on the choice of irreducible polynomial `f`. Care must be taken
    /// to ensure portability if these values might ever be passed to
    /// (or rederived within) another compilation environment where a
    /// different `f` might have been used.
    fn as_base_slice(&self) -> &[Base];

    /// Suppose this field extension is represented by the quotient
    /// ring `B[X]/f(X)` where `B` is `Base` and `f` is an irreducible
    /// polynomial of degree `D`. This function returns the field
    /// element `X^exponent` if `exponent < D` and panics otherwise.
    /// (The fact that `f` is not known at the point that this function
    /// is defined prevents implementing exponentiation of higher
    /// powers since the reduction cannot be performed.)
    ///
    /// NB: The value produced by this function fundamentally depends
    /// on the choice of irreducible polynomial `f`. Care must be taken
    /// to ensure portability if these values might ever be passed to
    /// (or rederived within) another compilation environment where a
    /// different `f` might have been used.
    fn monomial(exponent: usize) -> Self {
        assert!(exponent < Self::D, "requested monomial of too high degree");
        let mut vec = vec![Base::zero(); Self::D];
        vec[exponent] = Base::one();
        Self::from_base_slice(&vec)
    }
}

/// Extension field trait
pub trait ExtensionField<Base: Field + PackedField<Scalar = Base>>:
    AbstractExtensionField<Base>
{
    /// ExtensionPacking type
    type ExtensionPacking: AbstractExtensionField<Base>;

    /// Check is in base field or not.
    fn is_in_basefield(&self) -> bool {
        self.as_base_slice()[1..].iter().all(Base::is_zero)
    }

    /// Convert into base field.
    fn as_base(&self) -> Option<Base> {
        if self.is_in_basefield() {
            Some(self.as_base_slice()[0])
        } else {
            None
        }
    }

    /// Power packed
    // fn ext_powers_packed(&self) -> impl Iterator<Item = Self::ExtensionPacking> {
    fn ext_powers_packed(&self) -> Vec<Self::ExtensionPacking> {
        let powers: Vec<_> = powers(*self).take(Base::WIDTH + 1).collect();
        // Transpose first WIDTH powers
        let current = Self::ExtensionPacking::from_base_fn(|i| {
            Base::from_fn(|j| powers[j].as_base_slice()[i])
        });
        // Broadcast self^WIDTH
        let multiplier =
            Self::ExtensionPacking::from_base_fn(|i| powers[Base::WIDTH].as_base_slice()[i]);

        core::iter::successors(Some(current), move |&current| Some(current * multiplier)).collect()
    }
}

/// Binomial extension field trait.
/// A extension field with a irreducible polynomial `X^d-W`
/// such that the extension is `F[X]/(X^d-W)`.
pub trait BinomiallyExtendable<const D: usize>: Field {
    /// W
    fn w() -> Self;

    /// `DTH_ROOT = W^((n - 1)/D)`.
    ///
    /// `n` is the order of base field.
    ///
    /// Only works when exists `k` such that `n = kD + 1`.
    fn dth_root() -> Self;

    /// ext generator
    fn ext_generator() -> [Self; D];
}

///  Has Frobenius trait
pub trait HasFrobenius<F: Field + Packable>: ExtensionField<F> {
    /// frobenius
    fn frobenius(&self) -> Self;

    /// repeated_frobenius
    fn repeated_frobenius(&self, count: usize) -> Self;

    /// frobenius_inv
    fn frobenius_inv(&self) -> Self;

    /// minimal_poly
    fn minimal_poly(mut self) -> Vec<F> {
        let mut m = vec![Self::one()];
        for _ in 0..Self::D {
            m = naive_poly_mul(&m, &[-self, Self::ONE]);
            self = self.frobenius();
        }
        let mut m_iter = m
            .into_iter()
            .map(|c| c.as_base().expect("Extension is not algebraic?"));
        let m: Vec<F> = m_iter.by_ref().take(Self::D + 1).collect();
        debug_assert_eq!(m.len(), Self::D + 1);
        debug_assert_eq!(m.last(), Some(&F::ONE));
        debug_assert!(m_iter.all(|c| c.is_zero()));
        m
    }

    /// galois_group
    fn galois_group(self) -> Vec<Self> {
        iter::successors(Some(self), |x| Some(x.frobenius()))
            .take(Self::D)
            .collect()
    }
}

/// A field which supplies information like the two-adicity of its multiplicative group, and methods
/// for obtaining two-adic generators.
pub trait TwoAdicField: Field {
    /// The number of factors of two in this field's multiplicative group.
    const TWO_ADICITY: usize;

    /// Returns a generator of the multiplicative group of order `2^bits`.
    /// Assumes `bits < TWO_ADICITY`, otherwise the result is undefined.
    #[must_use]
    fn two_adic_generator(bits: usize) -> Self;
}

/// Optional trait for implementing Two Adic Binomial Extension Field.
pub trait HasTwoAdicBionmialExtension<const D: usize>: BinomiallyExtendable<D> {
    /// EXT_TWO_ADICITY
    const EXT_TWO_ADICITY: usize;

    /// ext_two_adic_generator
    fn ext_two_adic_generator(bits: usize) -> [Self; D];
}
