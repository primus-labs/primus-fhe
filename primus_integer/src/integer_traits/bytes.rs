/// Extension trait to provide access to bytes of integers.
pub trait ByteCount {
    /// The number of bytes this type has.
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
