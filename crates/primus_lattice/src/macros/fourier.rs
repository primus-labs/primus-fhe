//! Fourier-domain macros (Complex64 elements, no `FheUint` requirement).
//!
//! These macros generate iterator types, core methods, sub-component
//! iteration, and coefficient ↔ Fourier conversions for Fourier-domain
//! ciphertext variants (`FourierGlwe`, `FourierGlev`, `FourierGgsw`).

/// Generates `{Cipher}Iter<'a>` and `{Cipher}IterMut<'a>` chunked iterator
/// types for a Fourier ciphertext over `Complex64` elements.
macro_rules! impl_fourier_iters {
    ($cipher:ident) => {
        pastey::paste! {
            #[doc = "Immutable chunked iterator over [`" $cipher "`] ciphertexts."]
            #[derive(Debug, Clone)]
            pub struct [<$cipher Iter>]<'a> {
                iter: core::slice::ChunksExact<'a, num_complex::Complex64>,
            }

            impl<'a> [<$cipher Iter>]<'a> {
                #[doc = "Creates an iterator yielding [`" $cipher "`] views."]
                ///
                #[doc = "Each view contains `" [<$cipher:snake _len>] "` complex values."]
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// Each chunk must have the complete layout and representation documented
                /// for this ciphertext. Cryptographic metadata is neither inferred nor validated.
                ///
                /// # Panics
                ///
                #[doc = "Panics if `" [<$cipher:snake _len>] "` is zero."]
                #[must_use]
                #[inline]
                pub fn new(data: &'a [num_complex::Complex64], [<$cipher:snake _len>]: usize) -> Self {
                    Self {
                        iter: data.chunks_exact([<$cipher:snake _len>]),
                    }
                }
            }

            impl<'a> Iterator for [<$cipher Iter>]<'a> {
                type Item = $cipher<&'a [num_complex::Complex64]>;

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

            impl<'a> core::iter::FusedIterator for [<$cipher Iter>]<'a> {}
            impl<'a> core::iter::ExactSizeIterator for [<$cipher Iter>]<'a> {}
            impl<'a> core::iter::DoubleEndedIterator for [<$cipher Iter>]<'a> {
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
            pub struct [<$cipher IterMut>]<'a> {
                iter: core::slice::ChunksExactMut<'a, num_complex::Complex64>,
            }

            impl<'a> [<$cipher IterMut>]<'a> {
                #[doc = "Creates a mutable iterator yielding [`" $cipher "`] views."]
                ///
                #[doc = "Each view contains `" [<$cipher:snake _len>] "` complex values."]
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// Each chunk must have the complete layout and representation documented
                /// for this ciphertext. Cryptographic metadata is neither inferred nor validated.
                ///
                /// # Panics
                ///
                #[doc = "Panics if `" [<$cipher:snake _len>] "` is zero."]
                #[must_use]
                #[inline]
                pub fn new(data: &'a mut [num_complex::Complex64], [<$cipher:snake _len>]: usize) -> Self {
                    Self {
                        iter: data.chunks_exact_mut([<$cipher:snake _len>]),
                    }
                }
            }

            impl<'a> Iterator for [<$cipher IterMut>]<'a> {
                type Item = $cipher<&'a mut [num_complex::Complex64]>;

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

            impl<'a> core::iter::FusedIterator for [<$cipher IterMut>]<'a> {}
            impl<'a> core::iter::ExactSizeIterator for [<$cipher IterMut>]<'a> {}
            impl<'a> core::iter::DoubleEndedIterator for [<$cipher IterMut>]<'a> {
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

/// Generates the owned alias, constructors, storage views/conversions and
/// zeroing/size methods for a Fourier ciphertext.
macro_rules! impl_fourier_core {
    ($cipher:ident) => {
        pastey::paste! {
            #[doc = "Owned [`" $cipher "`] backed by a [`Vec`]."]
            pub type [<$cipher Owned>] = $cipher<Vec<num_complex::Complex64>>;
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64>,
        {
            #[doc = concat!(
                "Wraps the supplied Fourier-domain storage as a [`", stringify!($cipher), "<S>`]."
            )]
            ///
            /// # Correctness
            ///
            /// This only wraps storage. The caller must supply the complete layout and
            /// representation documented for this ciphertext; no cryptographic metadata
            /// is inferred or validated.
            #[must_use]
            #[inline]
            pub fn new(data: S) -> Self {
                Self(data)
            }

            /// Consumes the wrapper and returns its storage without copying.
            /// Borrowed storage remains borrowed; this does not create an owned buffer.
            #[must_use]
            #[inline]
            pub fn into_inner(self) -> S {
                self.0
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataOwned,
        {
            pastey::paste! {
                #[doc = "Creates a zero-initialized [`" $cipher "<S>`]."]
                ///
                /// The length is the total number of complex Fourier values,
                /// including every polynomial and ciphertext component.
                #[must_use]
                #[inline]
                pub fn zero([< $cipher:snake _len >]: usize) -> Self {
                    Self(S::from_vec(vec![
                        num_complex::Complex64::default();
                        [< $cipher:snake _len >]
                    ]))
                }
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
        {
            /// Sets all complex Fourier values to zero.
            #[inline]
            pub fn set_zero(&mut self) {
                self.0.fill(num_complex::Complex64::default());
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
        {
            /// Returns the total byte count.
            #[inline]
            pub fn byte_count(&self) -> usize {
                core::mem::size_of_val(self.0.as_slice())
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::Data<Elem = num_complex::Complex64>,
        {
            /// Borrows the complete storage as a shared view of the same representation.
            /// No elements are copied or transformed, and no layout is validated.
            #[must_use]
            #[inline]
            pub fn as_view(&self) -> $cipher<&[num_complex::Complex64]> {
                $cipher(self.0.as_slice())
            }
        }

        impl<'a, S> From<&'a $cipher<S>> for $cipher<&'a [num_complex::Complex64]>
        where
            S: primus_data::Data<Elem = num_complex::Complex64>,
        {
            #[inline]
            fn from(value: &'a $cipher<S>) -> Self {
                value.as_view()
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::DataMut<Elem = num_complex::Complex64>,
        {
            /// Borrows the complete storage as an exclusive view of the same representation.
            /// No elements are copied or transformed, and no layout is validated.
            #[must_use]
            #[inline]
            pub fn as_mut_view(&mut self) -> $cipher<&mut [num_complex::Complex64]> {
                $cipher(self.0.as_mut_slice())
            }
        }

        impl<'a, S> From<&'a mut $cipher<S>> for $cipher<&'a mut [num_complex::Complex64]>
        where
            S: primus_data::DataMut<Elem = num_complex::Complex64>,
        {
            #[inline]
            fn from(value: &'a mut $cipher<S>) -> Self {
                value.as_mut_view()
            }
        }

        impl<S> core::convert::AsRef<[num_complex::Complex64]> for $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
        {
            #[inline]
            fn as_ref(&self) -> &[num_complex::Complex64] {
                self.0.as_slice()
            }
        }

        impl<S> core::convert::AsMut<[num_complex::Complex64]> for $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
        {
            #[inline]
            fn as_mut(&mut self) -> &mut [num_complex::Complex64] {
                self.0.as_mut_slice()
            }
        }
    };
}

/// Generates sub-structure iteration methods for a Fourier ciphertext.
///
/// - `$sub`: the sub-component type
/// - `$sub_iter` / `$sub_iter_mut`: the sub-component's iterator types
/// - `$method`: the method name prefix (e.g., `fourier_poly` → `iter_fourier_poly`)
macro_rules! impl_fourier_iter_sub {
    ($cipher:ident, $sub:ident, $sub_iter:ident, $sub_iter_mut:ident, $method:ident) => {
        pastey::paste! {
            impl<S> $cipher<S>
            where
                S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
            {
                #[doc = "Returns an iterator over the [`" $sub "`] sub-components."]
                ///
                #[doc = "Each sub-component contains `" [<$method _len>] "` complex values."]
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// The chunk length must describe one complete sub-component.
                ///
                /// # Panics
                ///
                #[doc = "Panics if `" [<$method _len>] "` is zero."]
                #[inline]
                pub fn [<iter_ $method>](
                    &self,
                    [<$method _len>]: usize,
                ) -> $sub_iter<'_> {
                    $sub_iter::new(self.as_ref(), [<$method _len>])
                }
            }

            impl<S> $cipher<S>
            where
                S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
            {
                #[doc = "Returns a mutable iterator over the [`" $sub "`] sub-components."]
                ///
                #[doc = "Each sub-component contains `" [<$method _len>] "` complex values."]
                /// Any incomplete trailing chunk is omitted.
                ///
                /// # Correctness
                ///
                /// The chunk length must describe one complete sub-component.
                ///
                /// # Panics
                ///
                #[doc = "Panics if `" [<$method _len>] "` is zero."]
                #[inline]
                pub fn [<iter_ $method _mut>](
                    &mut self,
                    [<$method _len>]: usize,
                ) -> $sub_iter_mut<'_> {
                    $sub_iter_mut::new(self.0.as_mut_slice(), [<$method _len>])
                }
            }
        }
    };
}

/// Generates both coefficient-to-Fourier and Fourier-to-torus conversions.
macro_rules! impl_fourier_conversion {
    ($coeff:ident, $fourier:ident) => {
        impl<S, T> $coeff<S>
        where
            S: primus_data::RawData<Elem = T> + primus_data::Data,
            T: primus_fft::TorusFftValue,
        {
            /// Writes this ciphertext in normalized torus Fourier form.
            ///
            /// # Correctness
            ///
            /// Coefficient storage must consist of complete `fft.poly_length().get()` blocks;
            /// Fourier storage must consist of complete `fft.fourier_length()` blocks,
            /// with the same number and order of polynomials on both sides. The table,
            /// packing, and normalized torus scale must agree. Conversion can incur
            /// floating-point rounding error. Output is overwritten for each paired
            /// polynomial. Complete blocks and equal counts are assumed; incomplete
            /// or unmatched blocks can remain unprocessed. Empty paired batches are valid.
            pub fn write_fourier_form<Table, A>(
                &self,
                output: &mut $fourier<A>,
                fft: &mut primus_fft::FftEngine<'_, Table>,
            ) where
                Table: primus_fft::FftTable,
                A: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
            {
                let poly_length = fft.poly_length().get();
                let fourier_length = fft.fourier_length();
                for (coeff, mut fourier) in
                    primus_poly::PolynomialIter::new(self.as_ref(), poly_length).zip(
                        primus_poly::FourierPolynomialIterMut::new(output.as_mut(), fourier_length),
                    )
                {
                    fft.forward_as_torus(coeff.as_ref(), fourier.as_mut());
                }
            }
        }
        impl<S> $fourier<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
        {
            /// Writes this Fourier ciphertext back to torus coefficient form.
            ///
            /// # Correctness
            ///
            /// Coefficient storage must consist of complete `fft.poly_length().get()` blocks;
            /// Fourier storage must consist of complete `fft.fourier_length()` blocks,
            /// with the same number and order of polynomials on both sides. The table,
            /// packing, and normalized torus scale must agree. Conversion can incur
            /// floating-point rounding error. Output is overwritten for each paired
            /// polynomial. Complete blocks and equal counts are assumed; incomplete
            /// or unmatched blocks can remain unprocessed. Empty paired batches are valid.
            pub fn write_torus_form<Table, A, T>(
                &self,
                output: &mut $coeff<A>,
                fft: &mut primus_fft::FftEngine<'_, Table>,
            ) where
                Table: primus_fft::FftTable,
                A: primus_data::RawData<Elem = T> + primus_data::DataMut,
                T: primus_fft::TorusFftValue,
            {
                let poly_length = fft.poly_length().get();
                let fourier_length = fft.fourier_length();
                for (fourier, mut coeff) in
                    primus_poly::FourierPolynomialIter::new(self.as_ref(), fourier_length).zip(
                        primus_poly::PolynomialIterMut::new(output.as_mut(), poly_length),
                    )
                {
                    fft.backward_as_torus(fourier.as_ref(), coeff.as_mut());
                }
            }
        }
    };
}
