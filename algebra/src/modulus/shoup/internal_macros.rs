macro_rules! impl_shoup_factor {
    (impl ShoupFactor<$SelfT:ty>; WideType: $WideT:ty) => {
        impl ShoupFactor<$SelfT> {
            /// Constructs a [`ShoupFactor`].
            ///
            /// * `value` must be less than `modulus`.
            #[inline]
            pub const fn new(value: $SelfT, modulus: $SelfT) -> Self {
                debug_assert!(value < modulus);
                Self {
                    value,
                    quotient: (((value as $WideT) << <$SelfT>::BITS) / modulus as $WideT) as $SelfT,
                }
            }

            /// Resets the `modulus` of [`ShoupFactor`].
            #[inline]
            pub fn set_modulus(&mut self, modulus: $SelfT) {
                debug_assert!(self.value < modulus);
                self.quotient =
                    (((self.value as $WideT) << <$SelfT>::BITS) / modulus as $WideT) as $SelfT;
            }

            /// Resets the content of [`ShoupFactor`].
            ///
            /// * `value` must be less than `modulus`.
            #[inline]
            pub fn set(&mut self, value: $SelfT, modulus: $SelfT) {
                self.value = value;
                self.set_modulus(modulus);
            }

            /// Calculates `rhs * self.value mod modulus`.
            ///
            /// The result is in [0, 2 * `modulus`).
            ///
            /// # Proof
            ///
            /// Let `x = rhs`, `w = self.value`, `w' = self.quotient`, `p = modulus` and `β = 2^(64)`.
            ///
            /// By definition, `w' = ⌊wβ/p⌋`. Let `q = ⌊w'x/β⌋`.
            ///
            /// Then, `0 ≤ wβ/p - w' < 1`, `0 ≤ w'x/β - q < 1`.
            ///
            /// Multiplying by `xp/β` and `p` respectively, and adding, yields
            ///
            /// `0 ≤ wx - qp < xp/β + p < 2p < β`
            #[inline]
            pub fn mul_reduce_lazy(self, rhs: $SelfT, modulus: $SelfT) -> $SelfT {
                let hw = $crate::WideningMul::widening_mul_hw(self.quotient, rhs);
                self.value
                    .wrapping_mul(rhs)
                    .wrapping_sub(hw.wrapping_mul(modulus))
            }
        }
    };
}

macro_rules! impl_shoup_factor_ops {
    (impl ShoupFactor<$SelfT:ty>) => {
        impl $crate::reduce::MulReduce<Self, ShoupFactor<Self>> for $SelfT {
            type Output = Self;

            /// Calculates `self * rhs mod modulus`
            ///
            /// The result is in `[0, modulus)`
            ///
            /// # Correctness
            ///
            /// `rhs.value` must be less than `modulus`.
            #[inline]
            fn mul_reduce(self, rhs: ShoupFactor<Self>, modulus: Self) -> Self::Output {
                let tmp = rhs.mul_reduce_lazy(self, modulus);

                if tmp >= modulus {
                    tmp - modulus
                } else {
                    tmp
                }
            }
        }

        impl $crate::reduce::MulReduce<$SelfT, $SelfT> for ShoupFactor<$SelfT> {
            type Output = $SelfT;

            /// Calculates `self.value * rhs mod modulus`.
            ///
            /// The result is in `[0, modulus)`.
            #[inline]
            fn mul_reduce(self, rhs: $SelfT, modulus: $SelfT) -> Self::Output {
                let tmp = self.mul_reduce_lazy(rhs, modulus);

                if tmp >= modulus {
                    tmp - modulus
                } else {
                    tmp
                }
            }
        }

        impl $crate::reduce::MulReduceAssign<Self, ShoupFactor<Self>> for $SelfT {
            /// Calculates `self *= rhs mod modulus`.
            ///
            /// The result is in `[0, modulus)`.
            ///
            /// # Correctness
            ///
            /// `rhs.value` must be less than `modulus`.
            #[inline]
            fn mul_reduce_assign(&mut self, rhs: ShoupFactor<Self>, modulus: Self) {
                let tmp = rhs.mul_reduce_lazy(*self, modulus);
                *self = if tmp >= modulus { tmp - modulus } else { tmp };
            }
        }
    };
}
