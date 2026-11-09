//! Chunked iterator generation and sub-component iteration.
//!
//! These macros generate `{Type}Iter` / `{Type}IterMut` types and the
//! `iter_{sub}()` / `iter_{sub}_mut()` methods for navigating ciphertext
//! sub-structures.

macro_rules! impl_iters {
    ($cipher:ident) => {
        pastey::paste! {
            #[doc = "Immutable chunked iterator over [`" $cipher "`] ciphertexts."]
            #[derive(Debug, Clone)]
            pub struct [<$cipher Iter>]<'a, T>
            where
                T: FheUint,
            {
                /// Exact chunks backing this immutable ciphertext iterator.
                pub(crate) iter: core::slice::ChunksExact<'a, T>
            }

            impl<'a, T: FheUint> [<$cipher Iter>]<'a, T> {
                #[doc = "Creates an iterator yielding [`" $cipher "`] views."]
                ///
                #[doc = "Each view contains `" [<$cipher:snake _len>] "` elements."]
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// The chunk length must describe one complete sub-ciphertext in the
                /// intended layout.
                ///
                /// # Panics
                ///
                /// Panics if the chunk length is zero.
                #[inline]
                #[must_use]
                pub fn new(data:&'a [T], [<$cipher:snake _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact([<$cipher:snake _len>])
                    }
                }
            }

            impl<'a, T: FheUint> Iterator for [<$cipher Iter>]<'a, T> {
                type Item = $cipher<&'a [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map($cipher)
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }

                #[inline]
                fn count(self) -> usize {
                    self.iter.len()
                }

                #[inline]
                fn nth(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth(n).map($cipher)
                }

                #[inline]
                fn last(mut self) -> Option<Self::Item> {
                    self.next_back()
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$cipher Iter>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::ExactSizeIterator for [<$cipher Iter>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::DoubleEndedIterator for [<$cipher Iter>]<'a, T> {
                #[inline]
                fn next_back(&mut self) -> Option<Self::Item> {
                    self.iter.next_back().map($cipher)
                }

                #[inline]
                fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth_back(n).map($cipher)
                }
            }
        }

        pastey::paste! {
            #[doc = "Mutable chunked iterator over [`" $cipher "`] ciphertexts."]
            #[derive(Debug)]
            pub struct [<$cipher IterMut>]<'a, T>
            where
                T: FheUint,
            {
                /// Exact chunks backing this mutable ciphertext iterator.
                pub(crate) iter: core::slice::ChunksExactMut<'a, T>
            }

            impl<'a, T: FheUint> [<$cipher IterMut>]<'a, T> {
                #[doc = "Creates a mutable iterator yielding [`" $cipher "`] views."]
                ///
                #[doc = "Each view contains `" [<$cipher:snake _len>] "` elements."]
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// The chunk length must describe one complete sub-ciphertext in the
                /// intended layout.
                ///
                /// # Panics
                ///
                /// Panics if the chunk length is zero.
                #[inline]
                #[must_use]
                pub fn new(data:&'a mut [T], [<$cipher:snake _len>]:usize) -> Self{
                    Self {
                        iter: data.chunks_exact_mut([<$cipher:snake _len>])
                    }
                }
            }

            impl<'a, T: FheUint> Iterator for [<$cipher IterMut>]<'a, T> {
                type Item = $cipher<&'a mut [T]>;

                #[inline]
                fn next(&mut self) -> Option<Self::Item> {
                    self.iter.next().map($cipher)
                }

                #[inline]
                fn size_hint(&self) -> (usize, Option<usize>) {
                    self.iter.size_hint()
                }

                #[inline]
                fn count(self) -> usize {
                    self.iter.len()
                }

                #[inline]
                fn nth(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth(n).map($cipher)
                }

                #[inline]
                fn last(mut self) -> Option<Self::Item> {
                    self.next_back()
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$cipher IterMut>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::ExactSizeIterator for [<$cipher IterMut>]<'a, T> {}
            impl<'a, T: FheUint> core::iter::DoubleEndedIterator for [<$cipher IterMut>]<'a, T> {
                #[inline]
                fn next_back(&mut self) -> Option<Self::Item> {
                    self.iter.next_back().map($cipher)
                }

                #[inline]
                fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
                    self.iter.nth_back(n).map($cipher)
                }
            }
        }
    };
}

macro_rules! impl_iter_sub_structure {
    ($cipher:ident, $sub:ident) => {
        pastey::paste! {
            impl_iter_sub_structure!($cipher, $sub, [<$sub:snake>]);
        }
    };
    ($cipher:ident, $sub:ident, $sub_short:ident) => {
        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            pastey::paste! {
                #[doc = "Returns an iterator over the [`" $sub "`] sub-components of this [`" $cipher "<S>`]."]
                ///
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// The chunk length must describe one complete sub-ciphertext in the
                /// intended layout.
                ///
                /// # Panics
                ///
                /// Panics if the chunk length is zero.
                #[inline]
                pub fn [<iter_ $sub_short>]<'a>(&'a self, [<$sub_short _len>]: usize) -> [<$sub Iter>]<'a, T> {
                    [<$sub Iter>]::new(self.0.as_slice(), [<$sub_short _len>])
                }
            }
        }

        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            pastey::paste! {
                #[doc = "Returns a mutable iterator over the [`" $sub "`] sub-components of this [`" $cipher "<S>`]."]
                ///
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// The chunk length must describe one complete sub-ciphertext in the
                /// intended layout.
                ///
                /// # Panics
                ///
                /// Panics if the chunk length is zero.
                #[inline]
                pub fn [<iter_ $sub_short _mut>]<'a>(
                    &'a mut self,
                    [<$sub_short _len>]: usize,
                ) -> [<$sub IterMut>]<'a, T> {
                    [<$sub IterMut>]::new(self.0.as_mut_slice(), [<$sub_short _len>])
                }
            }
        }
    };
}
