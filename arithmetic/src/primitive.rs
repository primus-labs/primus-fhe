pub trait BigIntHelperMethods: Sized {
    type WideT;
    const BITS: u32;

    /// Calculates `self + rhs + carry` without the ability to overflow.
    ///
    /// Performs \"ternary addition\" which takes in an extra bit to add, and may return an
    /// additional bit of overflow. This allows for chaining together multiple additions
    /// to create \"big integers\" which represent larger values.
    ///
    /// This can be thought of as a 64-bit \"full adder\", in the electronics sense.
    ///
    /// # Examples
    ///
    /// Basic usage
    ///
    /// ```ignore
    /// assert_eq!(5u64.carry_add(2, false), (7, false));
    /// assert_eq!(5u64.carry_add(2, true), (8, false));
    /// assert_eq!(u64::MAX.carry_add(1, false), (0, true));
    /// assert_eq!(u64::MAX.carry_add(0, true), (0, true));
    /// assert_eq!(u64::MAX.carry_add(1, true), (1, true));
    /// assert_eq!(u64::MAX.carry_add(u64::MAX, true), (u64::MAX, true));
    /// ```
    ///
    /// If `carry` is false, this method is equivalent to
    /// [`overflowing_add`](https://doc.rust-lang.org/std/primitive.u64.html#method.overflowing_add):
    ///
    /// ```ignore
    /// assert_eq!(5_u64.carry_add(2, false), 5_u64.overflowing_add(2));
    /// assert_eq!(u64::MAX.carry_add(1, false), u64::MAX.overflowing_add(1));
    /// ```
    #[must_use = "this returns the result of the operation, \
                        without modifying the original"]
    fn carry_add(self, rhs: Self, carry: bool) -> (Self, bool);

    /// Calculates `self - rhs - borrow` without the ability to overflow.
    ///
    /// Performs \"ternary subtraction\" which takes in an extra bit to subtract, and may return
    /// an additional bit of overflow. This allows for chaining together multiple subtractions
    /// to create \"big integers\" which represent larger values.
    ///
    /// # Examples
    ///
    /// Basic usage
    ///
    /// ```ignore
    /// assert_eq!(5u64.borrow_sub(2, false), (3, false));
    /// assert_eq!(5u64.borrow_sub(2, true), (2, false));
    /// assert_eq!(0u64.borrow_sub(1, false), (u64::MAX, true));
    /// assert_eq!(0u64.borrow_sub(1, true), (u64::MAX - 1, true));
    /// ```
    #[must_use = "this returns the result of the operation, \
                      without modifying the original"]
    fn borrow_sub(self, rhs: Self, borrow: bool) -> (Self, bool);

    /// Calculates the complete product `self * rhs` without the possibility to overflow.
    ///
    /// This returns the low-order (wrapping) bits and the high-order (overflow) bits
    /// of the result as two separate values, in that order.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// Please note that this example is shared between integer types.
    /// Which explains why `u32` is used here.
    ///
    /// ```ignore
    /// assert_eq!(5u32.widen_mul(2), (10, 0));
    /// assert_eq!(1_000_000_000u32.widen_mul(10), (1410065408, 2));
    /// ```
    #[must_use = "this returns the result of the operation, \
                          without modifying the original"]
    fn widen_mul(self, rhs: Self) -> (Self, Self);

    /// Calculates the \"full multiplication\" `self * rhs + carry`
    /// without the possibility to overflow.
    ///
    /// This returns the low-order (wrapping) bits and the high-order (overflow) bits
    /// of the result as two separate values, in that order.
    ///
    /// Performs \"long multiplication\" which takes in an extra amount to add, and may return an
    /// additional amount of overflow. This allows for chaining together multiple
    /// multiplications to create \"big integers\" which represent larger values.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// Please note that this example is shared between integer types.
    /// Which explains why `u32` is used here.
    ///
    /// ```ignore
    /// assert_eq!(5u32.carry_mul(2, 0), (10, 0));
    /// assert_eq!(5u32.carry_mul(2, 10), (20, 0));
    /// assert_eq!(1_000_000_000u32.carry_mul(10, 0), (1410065408, 2));
    /// assert_eq!(1_000_000_000u32.carry_mul(10, 10), (1410065418, 2));
    /// assert_eq!(u64::MAX.carry_mul(u64::MAX, u64::MAX), (0, u64::MAX));
    /// ```
    ///
    /// If `carry` is zero, this is similar to
    /// [`overflowing_mul`](https://doc.rust-lang.org/std/primitive.u64.html#method.overflowing_mul),
    /// except that it gives the value of the overflow instead of just whether one happened:
    ///
    /// ```ignore
    /// let r = u8::carry_mul(7, 13, 0);
    /// assert_eq!((r.0, r.1 != 0), u8::overflowing_mul(7, 13));
    /// let r = u8::carry_mul(13, 42, 0);
    /// assert_eq!((r.0, r.1 != 0), u8::overflowing_mul(13, 42));
    /// ```
    ///
    /// The value of the first field in the returned tuple matches what you\'d get
    /// by combining the [`wrapping_mul`](https://doc.rust-lang.org/std/primitive.u64.html#method.wrapping_mul) and
    /// [`wrapping_add`](https://doc.rust-lang.org/std/primitive.u64.html#method.wrapping_add) methods:
    ///
    /// ```ignore
    /// assert_eq!(
    ///     789_u16.carry_mul(456, 123).0,
    ///     789_u16.wrapping_mul(456).wrapping_add(123),
    /// );
    /// ```
    #[must_use = "this returns the result of the operation, \
                      without modifying the original"]
    fn carry_mul(self, rhs: Self, carry: Self) -> (Self, Self);
}

impl BigIntHelperMethods for u64 {
    type WideT = u128;
    const BITS: u32 = 64;

    #[inline]
    fn carry_add(self, rhs: Self, carry: bool) -> (Self, bool) {
        let (a, b) = self.overflowing_add(rhs);
        let (c, d) = a.overflowing_add(carry as Self);
        (c, b || d)
    }

    #[inline]
    fn borrow_sub(self, rhs: Self, borrow: bool) -> (Self, bool) {
        let (a, b) = self.overflowing_sub(rhs);
        let (c, d) = a.overflowing_sub(borrow as Self);
        (c, b || d)
    }

    #[inline]
    fn widen_mul(self, rhs: Self) -> (Self, Self) {
        let wide = (self as Self::WideT) * (rhs as Self::WideT);
        (wide as Self, (wide >> Self::BITS) as Self)
    }

    #[inline]
    fn carry_mul(self, rhs: Self, carry: Self) -> (Self, Self) {
        let wide = (self as Self::WideT) * (rhs as Self::WideT) + (carry as Self::WideT);
        (wide as Self, (wide >> Self::BITS) as Self)
    }
}
