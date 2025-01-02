/// Performs numeric cast by `as`.
#[inline]
pub fn as_cast<T: Copy + AsInto<U>, U: Copy>(value: T) -> U {
    value.as_into()
}

/// A helper trait defines all `as` cast between all primitive integer types.
pub trait AsCast:
    AsFrom<i8>
    + AsFrom<u8>
    + AsFrom<i16>
    + AsFrom<u16>
    + AsFrom<i32>
    + AsFrom<u32>
    + AsFrom<i64>
    + AsFrom<u64>
    + AsFrom<i128>
    + AsFrom<u128>
    + AsFrom<isize>
    + AsFrom<usize>
    + AsFrom<f32>
    + AsFrom<f64>
    + AsInto<i8>
    + AsInto<u8>
    + AsInto<i16>
    + AsInto<u16>
    + AsInto<i32>
    + AsInto<u32>
    + AsInto<i64>
    + AsInto<u64>
    + AsInto<i128>
    + AsInto<u128>
    + AsInto<isize>
    + AsInto<usize>
    + AsInto<f32>
    + AsInto<f64>
{
}

macro_rules! impl_as_cast {
    ($($T: ty),*) => {$(
        impl AsCast for $T {}
    )*};
}

impl_as_cast! {u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize}

/// A trait to convert from type `T` by `as`.
pub trait AsFrom<T: Copy>: Copy {
    /// Convert `value` from type `T` into `Self` by `as`.
    fn as_from(value: T) -> Self;
}

/// A trait to convert `self` into type `T` by `as`.
pub trait AsInto<T: Copy>: Copy {
    /// Convert `self` from type `Self` into `T` by `as`.
    fn as_into(self) -> T;
}

impl<T: Copy, U: Copy> AsInto<T> for U
where
    T: AsFrom<U>,
{
    #[inline]
    fn as_into(self) -> T {
        T::as_from(self)
    }
}

impl<T: Copy> AsFrom<T> for T {
    #[inline(always)]
    fn as_from(value: T) -> Self {
        value
    }
}

macro_rules! impl_as_from {
    (@ $T: ty => $(#[$cfg:meta])* impl $U: ty ) => {
        $(#[$cfg])*
        impl AsFrom<$T> for $U {
            #[inline] fn as_from(value: $T) -> $U { value as $U }
        }
    };
    ($T: ty => { $( $U: ty ),* } ) => {$(
        impl_as_from!(@ $T => impl $U);
    )*};
}

impl_as_from!(u8 => { char, f32, f64, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i8 => { f32, f64, u8, u16, u32, u64, u128, usize, i16, i32, i64, i128, isize });
impl_as_from!(u16 => { f32, f64, u8, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i16 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i32, i64, i128, isize });
impl_as_from!(u32 => { f32, f64, u8, u16, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i32 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i64, i128, isize });
impl_as_from!(u64 => { f32, f64, u8, u16, u32, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i64 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i128, isize });
impl_as_from!(u128 => { f32, f64, u8, u16, u32, u64, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(i128 => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, isize });
impl_as_from!(usize => { f32, f64, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, isize });
impl_as_from!(isize => { f32, f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128 });
impl_as_from!(f32 => { f64, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(f64 => { f32, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(char => { u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
impl_as_from!(bool => { u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize });
