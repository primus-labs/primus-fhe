/// Generate `<BigUint>Iter` / `<BigUint>IterMut` chunk-iterators for a wrapper type.
///
/// Given a wrapper `$big_uint` of the form `pub struct $big_uint<S>(S)` over slice
/// storage, expands to two iterator types — `<$big_uint>Iter` and
/// `<$big_uint>IterMut` — that walk the underlying buffer in fixed-size chunks of
/// `[<$short_name _len>]` elements and yield `$big_uint<&[T]>` / `$big_uint<&mut [T]>`
/// items. Used to give big-integer/polynomial wrappers row-iteration without
/// duplicating boilerplate per wrapper type.
///
/// # Arguments
///
/// * `$big_uint` — the wrapper type name (e.g. `BigUint`).
/// * `$short_name` — short label used to derive the chunk-length parameter
///   name (e.g. `bit_uint` → `bit_uint_len`).
#[macro_export]
macro_rules! impl_iters {
    ($big_uint:ident, $short_name:ident) => {
        paste::paste! {
            /// Iterator over non-overlapping chunks of a `$big_uint` buffer.
            pub struct [<$big_uint Iter>]<'a, T>
            where
                T: UnsignedInteger,
            {
                /// The underlying chunk iterator.
                pub iter: core::slice::ChunksExact<'a, T>
            }

            impl<'a, T: UnsignedInteger> [<$big_uint Iter>]<'a, T> {
                /// Creates a new iterator over `$big_uint` chunks of the given length.
                #[inline]
                pub fn new(data:&'a [T], [<$short_name _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact([<$short_name _len>])
                    }
                }
            }

            impl<'a, T: UnsignedInteger> Iterator for [<$big_uint Iter>]<'a, T> {
                type Item = $big_uint<&'a [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map(|slice| $big_uint(slice))
                }
            }

            impl<'a, T: UnsignedInteger> core::iter::FusedIterator for [<$big_uint Iter>]<'a, T> {}
        }

        paste::paste! {
            /// Mutable iterator over non-overlapping chunks of a `$big_uint` buffer.
            pub struct [<$big_uint IterMut>]<'a, T>
            where
                T: UnsignedInteger,
            {
                /// The underlying mutable chunk iterator.
                pub iter: core::slice::ChunksExactMut<'a, T>
            }

            impl<'a, T: UnsignedInteger> [<$big_uint IterMut>]<'a, T> {
                /// Creates a new mutable iterator over `$big_uint` chunks of the given length.
                #[inline]
                pub fn new(data:&'a mut [T], [<$short_name _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact_mut([<$short_name _len>])
                    }
                }
            }

            impl<'a, T: UnsignedInteger> Iterator for [<$big_uint IterMut>]<'a, T> {
                type Item = $big_uint<&'a mut [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map(|slice| $big_uint(slice))
                }
            }

            impl<'a, T: UnsignedInteger> core::iter::FusedIterator for [<$big_uint IterMut>]<'a, T> {}
        }
    };
}
