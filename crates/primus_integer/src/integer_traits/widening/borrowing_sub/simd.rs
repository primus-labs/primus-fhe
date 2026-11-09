use core::simd::{Mask, Simd, SimdElement, cmp::SimdPartialOrd, num::SimdInt};

use super::BorrowingSub;

macro_rules! simd_uint_borrowing_sub_impl {
    ($($T:ty),+) => {
        $(
            impl<const N:usize> BorrowingSub for Simd<$T, N>
            {
                type BorrowT = Mask<<$T as SimdElement>::Mask, N>;

                #[inline]
                fn borrowing_sub(self, rhs: Self, borrow: Self::BorrowT) -> (Self, Self::BorrowT) {
                    let difference = self - rhs;
                    // A true mask lane becomes an all-ones unsigned word, so
                    // adding it subtracts one modulo the word radix.
                    let difference_with_borrow = difference + borrow.to_simd().cast();
                    let borrow_out =
                        difference.simd_gt(self) | difference_with_borrow.simd_gt(difference);
                    (difference_with_borrow, borrow_out)
                }
            }
        )+
    };
}

simd_uint_borrowing_sub_impl! {u8, u16, u32, u64, usize}
