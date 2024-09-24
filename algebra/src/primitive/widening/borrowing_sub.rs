/// Borrowing sub operation trait
pub trait BorrowingSub: Sized {
    /// The type of `borrow`.
    type MaskT;

    /// Calculates `self` - `rhs` - `borrow` and returns a tuple containing
    /// the difference and the output borrow.
    ///
    /// Performs "ternary subtraction" by subtracting both an integer operand and a borrow-in bit from self,
    /// and returns an output integer and a borrow-out bit. This allows chaining together multiple subtractions
    /// to create a wider subtraction, and can be useful for bignum subtraction.
    fn borrowing_sub(self, rhs: Self, borrow: Self::MaskT) -> (Self, Self::MaskT);
}

macro_rules! uint_borrowing_sub_impl {
    ($($SelfT:ty),*) => {
        $(
            impl BorrowingSub for $SelfT {
                type MaskT = bool;

                #[inline]
                fn borrowing_sub(self, rhs: Self, borrow: bool) -> (Self, bool) {
                    #[cfg(feature = "nightly")]
                    {
                        self.borrowing_sub(rhs, borrow)
                    }

                    #[cfg(not(feature = "nightly"))]
                    {
                        let (a, b) = self.overflowing_sub(rhs);
                        let (c, d) = a.overflowing_sub(borrow as Self);
                        (c, b || d)
                    }
                }
            }
        )*
    };
}

uint_borrowing_sub_impl!(u8, u16);

#[cfg(all(not(feature = "nightly"), target_arch = "x86"))]
#[inline]
fn subborrow_u32(a: u32, b: u32, borrow: bool) -> (u32, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86::_subborrow_u32(borrow as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(all(not(feature = "nightly"), target_arch = "x86_64"))]
#[inline]
fn subborrow_u32(a: u32, b: u32, borrow: bool) -> (u32, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86_64::_subborrow_u32(borrow as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(not(any(feature = "nightly", target_arch = "x86_64", target_arch = "x86")))]
#[inline]
fn subborrow_u32(a: u32, b: u32, borrow: bool) -> (u32, bool) {
    let (a, b) = a.overflowing_sub(b);
    let (c, d) = a.overflowing_sub(borrow as u32);
    (c, b || d)
}

impl BorrowingSub for u32 {
    type MaskT = bool;

    #[inline]
    fn borrowing_sub(self, rhs: Self, borrow: Self::MaskT) -> (Self, Self::MaskT) {
        #[cfg(feature = "nightly")]
        {
            self.borrowing_sub(rhs, borrow)
        }

        #[cfg(not(feature = "nightly"))]
        {
            subborrow_u32(self, rhs, borrow)
        }
    }
}

#[cfg(all(not(feature = "nightly"), target_arch = "x86"))]
#[inline]
fn subborrow_u64(a: u64, b: u64, borrow: bool) -> (u64, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86::_subborrow_u64(borrow as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(all(not(feature = "nightly"), target_arch = "x86_64"))]
#[inline]
fn subborrow_u64(a: u64, b: u64, borrow: bool) -> (u64, bool) {
    let mut t = 0;
    let c = unsafe { core::arch::x86_64::_subborrow_u64(borrow as u8, a, b, &mut t) };
    (t, c != 0)
}

#[cfg(not(any(feature = "nightly", target_arch = "x86_64", target_arch = "x86")))]
#[inline]
fn subborrow_u64(a: u64, b: u64, borrow: bool) -> (u64, bool) {
    let (a, b) = a.overflowing_sub(b);
    let (c, d) = a.overflowing_sub(borrow as u64);
    (c, b || d)
}

impl BorrowingSub for u64 {
    type MaskT = bool;

    #[inline]
    fn borrowing_sub(self, rhs: Self, borrow: Self::MaskT) -> (Self, Self::MaskT) {
        #[cfg(feature = "nightly")]
        {
            self.borrowing_sub(rhs, borrow)
        }

        #[cfg(not(feature = "nightly"))]
        {
            subborrow_u64(self, rhs, borrow)
        }
    }
}
