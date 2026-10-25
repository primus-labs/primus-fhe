/// A type with an associated constant representing the value `2`.
///
/// This trait complements [`num_traits::ConstZero`] and
/// [`num_traits::ConstOne`] by making `2` available to generic integer code
/// without converting an integer literal to a concrete type.
pub trait ConstTwo {
    /// The value `2` in this type.
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

impl_two! {i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize}
