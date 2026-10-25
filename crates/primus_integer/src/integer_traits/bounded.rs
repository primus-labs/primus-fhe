/// A type whose minimum and maximum representable values are available as
/// associated constants.
///
/// This trait makes the inherent `MIN` and `MAX` constants of primitive
/// integers available to generic code.
pub trait ConstBounded {
    /// The smallest value representable by this type.
    const MIN: Self;

    /// The largest value representable by this type.
    const MAX: Self;
}

macro_rules! impl_bounded {
    ($($T:ty),*) => {
        $(
            impl ConstBounded for $T {
                const MIN: Self = <$T>::MIN;
                const MAX: Self = <$T>::MAX;
            }
        )*
    };
}

impl_bounded! {i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize}
