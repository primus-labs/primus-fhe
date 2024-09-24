/// Carrying add operation trait
pub trait CarryingAdd: Sized {
    /// The type of `carry`.
    type MaskT;

    /// Calculates `self` + `rhs` + `carry` and checks for overflow.
    ///
    /// Performs “ternary addition” of two integer operands and a carry-in bit,
    /// and returns a tuple of the sum along with a boolean indicating
    /// whether an arithmetic overflow would occur. On overflow, the wrapped value is returned.
    ///
    /// This allows chaining together multiple additions to create a wider addition,
    /// and can be useful for bignum addition.
    /// This method should only be used for the most significant word.
    ///
    /// The output boolean returned by this method is not a carry flag,
    /// and should not be added to a more significant word.
    ///
    /// If the input carry is false, this method is equivalent to `overflowing_add`.
    fn carrying_add(self, rhs: Self, carry: Self::MaskT) -> (Self, Self::MaskT);
}

macro_rules! uint_carrying_add_impl {
    ($($SelfT:ty),*) => {
        $(
            impl CarryingAdd for $SelfT {
                type MaskT = bool;

                #[inline]
                fn carrying_add(self, rhs: Self, carry: bool) -> (Self, bool) {
                    #[cfg(feature = "nightly")]
                    {
                        self.carrying_add(rhs, carry)
                    }

                    #[cfg(not(feature = "nightly"))]
                    {
                        let (a, b) = self.overflowing_add(rhs);
                        let (c, d) = a.overflowing_add(carry as Self);
                        (c, b || d)
                    }
                }
            }
        )*
    };
}

uint_carrying_add_impl!(u8, u16);

#[cfg(all(not(feature = "nightly"), target_arch = "x86"))]
#[inline]
fn addcarry_u32(a: u32, b: u32, carry: bool) -> (u32, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86::_addcarry_u32(carry as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(all(not(feature = "nightly"), target_arch = "x86_64"))]
#[inline]
fn addcarry_u32(a: u32, b: u32, carry: bool) -> (u32, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86_64::_addcarry_u32(carry as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(not(any(feature = "nightly", target_arch = "x86_64", target_arch = "x86")))]
#[inline]
fn addcarry_u32(a: u32, b: u32, carry: bool) -> (u32, bool) {
    let (a, b) = a.overflowing_add(b);
    let (c, d) = a.overflowing_add(carry as u32);
    (c, b || d)
}

impl CarryingAdd for u32 {
    type MaskT = bool;

    #[inline]
    fn carrying_add(self, rhs: Self, carry: Self::MaskT) -> (Self, Self::MaskT) {
        #[cfg(feature = "nightly")]
        {
            self.carrying_add(rhs, carry)
        }

        #[cfg(not(feature = "nightly"))]
        {
            addcarry_u32(self, rhs, carry)
        }
    }
}

#[cfg(all(not(feature = "nightly"), target_arch = "x86"))]
#[inline]
fn addcarry_u64(a: u64, b: u64, carry: bool) -> (u64, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86::_addcarry_u64(carry as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(all(not(feature = "nightly"), target_arch = "x86_64"))]
#[inline]
fn addcarry_u64(a: u64, b: u64, carry: bool) -> (u64, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86_64::_addcarry_u64(carry as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(not(any(feature = "nightly", target_arch = "x86_64", target_arch = "x86")))]
#[inline]
fn addcarry_u64(a: u64, b: u64, carry: bool) -> (u64, bool) {
    let (a, b) = a.overflowing_add(b);
    let (c, d) = a.overflowing_add(carry as u64);
    (c, b || d)
}

impl CarryingAdd for u64 {
    type MaskT = bool;

    #[inline]
    fn carrying_add(self, rhs: Self, carry: Self::MaskT) -> (Self, Self::MaskT) {
        #[cfg(feature = "nightly")]
        {
            self.carrying_add(rhs, carry)
        }

        #[cfg(not(feature = "nightly"))]
        {
            addcarry_u64(self, rhs, carry)
        }
    }
}
