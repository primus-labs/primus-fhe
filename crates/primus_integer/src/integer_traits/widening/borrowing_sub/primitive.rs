use super::BorrowingSub;

macro_rules! impl_uint_borrowing_sub {
    ($($T:ty),*) => {
        $(
            impl BorrowingSub for $T {
                type BorrowT = bool;

                #[inline]
                fn borrowing_sub(self, rhs: Self, borrow: Self::BorrowT) -> (Self, Self::BorrowT) {
                    <$T>::borrowing_sub(self, rhs, borrow)
                }
            }
        )*
    };
}

impl_uint_borrowing_sub! {u8, u16, u32, u64, u128, usize}
