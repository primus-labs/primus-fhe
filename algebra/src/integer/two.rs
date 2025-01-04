/// Defines an associated constant representing `2` for `Self`.
pub trait ConstTwo {
    /// `2`
    const TWO: Self;
}

macro_rules! impl_two {
    ($($T:ty),*) => {
        $(
            impl ConstTwo for $T {
                const TWO: Self = 2;
            }
        )*
    };
}

impl_two!(i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize);
