/// Numbers which have upper and lower bounds
pub trait ConstBounded {
    /// The smallest finite number this type can represent
    const MIN: Self;
    /// The largest finite number this type can represent
    const MAX: Self;
}

macro_rules! bounded_impl {
    ($($T:ty),*) => {
        $(
            impl ConstBounded for $T {
                const MIN: Self = <$T>::MIN;
                const MAX: Self = <$T>::MAX;
            }
        )*
    };
}

bounded_impl!(i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize);
