macro_rules! impl_iters {
    ($poly:ident, $short_name:ident) => {
        pastey::paste! {
            #[doc = "Immutable chunked iterator over [`" $poly "`] elements."]
            #[derive(Debug, Clone)]
            pub struct [<$poly Iter>]<'a, T>
            where
                T: FheUint,
            {
                /// The underlying chunked iterator.
                iter: core::slice::ChunksExact<'a, T>
            }

            impl<'a, T: FheUint> [<$poly Iter>]<'a, T> {
                #[doc = "Creates a [`" [<$poly Iter>] "`] from the data slice and chunk size."]
                ///
                /// Any trailing elements that do not fill a complete chunk are not yielded.
                ///
                /// # Panics
                ///
                /// Panics if the chunk size is zero.
                #[must_use]
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

        pastey::paste! {
            #[doc = "Mutable chunked iterator over [`" $poly "`] elements."]
            #[derive(Debug)]
            pub struct [<$poly IterMut>]<'a, T>
            where
                T: FheUint,
            {
                /// The underlying mutable chunked iterator.
                iter: core::slice::ChunksExactMut<'a, T>
            }

            impl<'a, T: FheUint> [<$poly IterMut>]<'a, T> {
                #[doc = "Creates a [`" [<$poly IterMut>] "`] from the data slice and chunk size."]
                ///
                /// Any trailing elements that do not fill a complete chunk are not yielded.
                ///
                /// # Panics
                ///
                /// Panics if the chunk size is zero.
                #[must_use]
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

/// Storage views, conversions and unwrapping for integer polynomial representations.
macro_rules! impl_views {
    ($poly:ident) => {
        impl<S, T> $poly<S>
        where
            S: RawData<Elem = T>,
            T: FheUint,
        {
            /// Consumes the wrapper and returns its storage without copying.
            /// Borrowed storage remains borrowed; this does not create an owned buffer.
            #[must_use]
            #[inline]
            pub fn into_inner(self) -> S {
                self.0
            }
        }

        impl<S, T> $poly<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Borrows the complete storage as a shared view of the same representation.
            /// No elements are copied or transformed, and no layout is validated.
            #[must_use]
            #[inline]
            pub fn as_view(&self) -> $poly<&[T]> {
                $poly(self.0.as_slice())
            }
        }

        impl<'a, S, T> From<&'a $poly<S>> for $poly<&'a [T]>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            #[inline]
            fn from(value: &'a $poly<S>) -> Self {
                value.as_view()
            }
        }

        impl<S, T> $poly<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Borrows the complete storage as an exclusive view of the same representation.
            /// No elements are copied or transformed, and no layout is validated.
            #[must_use]
            #[inline]
            pub fn as_mut_view(&mut self) -> $poly<&mut [T]> {
                $poly(self.0.as_mut_slice())
            }
        }

        impl<'a, S, T> From<&'a mut $poly<S>> for $poly<&'a mut [T]>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            #[inline]
            fn from(value: &'a mut $poly<S>) -> Self {
                value.as_mut_view()
            }
        }
    };
}
