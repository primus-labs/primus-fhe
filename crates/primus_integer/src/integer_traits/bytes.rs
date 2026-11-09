/// An integer type whose in-memory size is available as an associated constant.
///
/// This trait gives generic code a common way to obtain the storage size of
/// primitive integers. The size of `isize` and `usize` depends on the target's
/// pointer width.
pub trait ByteCount {
    /// The size, in bytes, of a value of this type.
    const BYTES: usize;
}

macro_rules! impl_bytes {
    ($($T:ty),*) => {
        $(
            impl ByteCount for $T {
                const BYTES: usize = std::mem::size_of::<Self>();
            }
        )*
    };
}

impl_bytes!(
    i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize
);
