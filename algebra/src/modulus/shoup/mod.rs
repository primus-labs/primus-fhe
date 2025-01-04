use crate::integer::{AsFrom, AsInto};
use crate::numeric::Numeric;

mod ops;

/// A number used for fast modular multiplication.
///
/// This is efficient if many operations are multiplied by
/// the same number and then reduced with the same modulus.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShoupFactor<T: Numeric> {
    /// value
    value: T,

    /// quotient
    quotient: T,
}

impl<T: Numeric> ShoupFactor<T> {
    /// Constructs a [`ShoupFactor<T>`].
    ///
    /// * `value` must be less than `modulus`.
    #[inline]
    pub fn new(value: T, modulus: T) -> Self {
        debug_assert!(value < modulus);
        Self {
            value,
            quotient: ((<T::WideT>::as_from(value) << T::BITS) / <T::WideT>::as_from(modulus))
                .as_into(),
        }
    }

    /// Resets the `modulus` of [`ShoupFactor<T>`].
    #[inline]
    pub fn set_modulus(&mut self, modulus: T) {
        debug_assert!(self.value < modulus);
        self.quotient =
            ((<T::WideT>::as_from(self.value) << T::BITS) / <T::WideT>::as_from(modulus)).as_into();
    }

    /// Resets the content of [`ShoupFactor<T>`].
    ///
    /// * `value` must be less than `modulus`.
    #[inline]
    pub fn set(&mut self, value: T, modulus: T) {
        self.value = value;
        self.set_modulus(modulus);
    }

    /// Returns the value of this [`ShoupFactor<T>`].
    #[inline]
    pub const fn value(self) -> T {
        self.value
    }

    /// Returns the quotient of this [`ShoupFactor<T>`].
    #[inline]
    pub const fn quotient(self) -> T {
        self.quotient
    }
}
