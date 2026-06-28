macro_rules! impl_iters {
    ($poly:ident, $short_name:ident) => {
        paste::paste! {
            #[doc = concat!("Immutable chunked iterator over [`", stringify!($poly), "`] elements.")]
            #[derive(Debug, Clone)]
            pub struct [<$poly Iter>]<'a, T>
            where
                T: FheUint,
            {
                /// The underlying chunked iterator.
                pub iter: core::slice::ChunksExact<'a, T>
            }

            impl<'a, T: FheUint> [<$poly Iter>]<'a, T> {
                #[doc = concat!("Creates a new [`", stringify!($poly), "Iter`] from the data slice and chunk size.")]
                #[inline]
                pub fn new(data:&'a [T], [<$short_name _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact([<$short_name _len>])
                    }
                }
            }

            impl<'a, T: FheUint> Iterator for [<$poly Iter>]<'a, T> {
                type Item = $poly<&'a [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map(|slice| $poly(slice))
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }

                #[inline]
                fn count(self) -> usize {
                    self.len()
                }

                #[inline]
                fn nth(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth(n).map(|slice| $poly(slice))
                }

                #[inline]
                fn last(mut self) -> Option<Self::Item> {
                    self.next_back()
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$poly Iter>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::DoubleEndedIterator for [<$poly Iter>]<'a, T> {
                #[inline]
                fn next_back(&mut self) -> Option<Self::Item> {
                    self.iter.next_back().map(|slice| $poly(slice))
                }

                #[inline]
                fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth_back(n).map(|slice| $poly(slice))
                }
            }
            impl<'a, T: FheUint> core::iter::ExactSizeIterator for [<$poly Iter>]<'a, T> {}
        }

        paste::paste! {
            #[doc = concat!("Mutable chunked iterator over [`", stringify!($poly), "`] elements.")]
            #[derive(Debug)]
            pub struct [<$poly IterMut>]<'a, T>
            where
                T: FheUint,
            {
                /// The underlying mutable chunked iterator.
                pub iter: core::slice::ChunksExactMut<'a, T>
            }

            impl<'a, T: FheUint> [<$poly IterMut>]<'a, T> {
                #[doc = concat!("Creates a new mutable [`", stringify!($poly), "IterMut`] from the data slice and chunk size.")]
                #[inline]
                pub fn new(data:&'a mut [T], [<$short_name _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact_mut([<$short_name _len>])
                    }
                }
            }

            impl<'a, T: FheUint> Iterator for [<$poly IterMut>]<'a, T> {
                type Item = $poly<&'a mut [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map(|slice| $poly(slice))
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }

                #[inline]
                fn count(self) -> usize {
                    self.len()
                }

                #[inline]
                fn nth(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth(n).map(|slice| $poly(slice))
                }

                #[inline]
                fn last(mut self) -> Option<Self::Item> {
                    self.next_back()
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$poly IterMut>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::DoubleEndedIterator for [<$poly IterMut>]<'a, T> {
                #[inline]
                fn next_back(&mut self) -> Option<Self::Item> {
                    self.iter.next_back().map(|slice| $poly(slice))
                }

                #[inline]
                fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth_back(n).map(|slice| $poly(slice))
                }
            }
            impl<'a, T: FheUint> core::iter::ExactSizeIterator for [<$poly IterMut>]<'a, T> {}
        }
    };
}
