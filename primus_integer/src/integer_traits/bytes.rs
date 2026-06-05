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

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_bytes_per_type {
        ($($T:ty),*; $($W:literal),*) => {
            $(
                assert_eq!(<$T as ByteCount>::BYTES, $W);
            )*
        };
    }

    #[test]
    fn test_bytes() {
        #[cfg(target_pointer_width = "32")]
        test_bytes_per_type!(
            i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize;
             1,  1,   2,   2,   4,   4,   8,   8,   16,   16,     4,     4
        );
        #[cfg(target_pointer_width = "64")]
        test_bytes_per_type!(
            i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize;
             1,  1,   2,   2,   4,   4,   8,   8,   16,   16,     8,     8
        );
    }
}
