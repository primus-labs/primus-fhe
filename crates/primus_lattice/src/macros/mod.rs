macro_rules! impl_common {
    ($cipher:ident < $s:ident >) => {
        impl<$s> $cipher<$s>
        where
            $s: RawData,
            <$s as RawData>::Elem: FheUint,
        {
            #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!($s),">`].")]
            #[inline(always)]
            pub fn new(data: $s) -> Self {
                Self(data)
            }
        }

        impl<$s, T> AsRef<[T]> for $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            #[inline(always)]
            fn as_ref(&self) -> &[T] {
                self.0.as_slice()
            }
        }

        impl<$s, T> AsMut<[T]> for $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            #[inline(always)]
            fn as_mut(&mut self) -> &mut [T] {
                self.0.as_mut_slice()
            }
        }
    };
}

macro_rules! impl_bytes_conversion {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataOwned,
            T: FheUint,
        {
            #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!($s),">`] from bytes `data`.")]
            #[inline]
            pub fn from_bytes(data: &[u8]) -> Self {
                let converted_data: &[T] = bytemuck::cast_slice(data);

                Self(<$s>::from_slice(converted_data))
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Copy from bytes `data`.
            #[inline]
            pub fn read_bytes(&mut self, data: &[u8]) {
                let converted_data: &[T] = bytemuck::cast_slice(data);

                self.0.copy_from_slice(converted_data);
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Converts `self` into bytes.
            #[inline]
            pub fn to_bytes(&self) -> Vec<u8> {
                let converted_data: &[u8] = bytemuck::cast_slice(self.as_ref());

                converted_data.to_vec()
            }

            /// Converts `self` into bytes, stored in `data`.
            #[inline]
            pub fn write_bytes(&self, data: &mut [u8]) {
                let converted_data: &[u8] = bytemuck::cast_slice(self.as_ref());

                data.copy_from_slice(converted_data);
            }

            /// Returns the bytes count.
            #[inline]
            pub fn byte_count(&self) -> usize {
                self.0.len() * T::BYTES
            }
        }
    };
}

macro_rules! impl_zero {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataOwned,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!(r" Creates a new [`",stringify!($cipher),"<",stringify!($s),">`] with all values or coefficients equal to zero.")]
                #[inline]
                pub fn zero([<$cipher:snake _len>]: usize) -> Self {
                    Self(<$s>::from_vec(vec![T::ZERO; [<$cipher:snake _len>]]))
                }
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Set all values or coefficients equal to zero.
            #[inline]
            pub fn set_zero(&mut self) {
                self.0.fill(T::ZERO);
            }
        }
    };
}
macro_rules! impl_iters {
    ($cipher:ident) => {
        paste::paste! {
            #[doc = concat!("Immutable chunked iterator over [`", stringify!($cipher), "`] ciphertexts.")]
            pub struct [<$cipher Iter>]<'a, T>
            where
                T: FheUint,
            {
                pub(crate) iter: core::slice::ChunksExact<'a, T>
            }

            impl<'a, T: FheUint> [<$cipher Iter>]<'a, T> {
                #[doc = concat!("Creates an iterator yielding `", stringify!($cipher), "` chunks of `", stringify!([<$cipher:snake _len>]), "` elements each.")]
                #[inline]
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
                    self.iter.next().map(|slice| $cipher(slice))
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$cipher Iter>]<'a, T> {}
        }

        paste::paste! {
            #[doc = concat!("Mutable chunked iterator over [`", stringify!($cipher), "`] ciphertexts.")]
            pub struct [<$cipher IterMut>]<'a, T>
            where
                T: FheUint,
            {
                pub(crate) iter: core::slice::ChunksExactMut<'a, T>
            }

            impl<'a, T: FheUint> [<$cipher IterMut>]<'a, T> {
                #[doc = concat!("Creates a mutable iterator yielding `", stringify!($cipher), "` chunks of `", stringify!([<$cipher:snake _len>]), "` elements each.")]
                #[inline]
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
                    self.iter.next().map(|slice| $cipher(slice))
                }
            }

            impl<'a, T: FheUint> core::iter::FusedIterator for [<$cipher IterMut>]<'a, T> {}
        }
    };
}

macro_rules! impl_iter_sub_structure {
    ($cipher:ident < $s:ident >, $sub:ident) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns an iterator over the `", stringify!($sub), "` sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub:snake>]<'a>(&'a self, [<$sub:snake _len>]: usize) -> [<$sub Iter>]<'a, T> {
                    [<$sub Iter>] {
                        iter: self.0.chunks_exact([<$sub:snake _len>])
                    }

                }
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns a mutable iterator over the `", stringify!($sub), "` sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub:snake _mut>]<'a>(
                    &'a mut self,
                    [<$sub:snake _len>]: usize,
                ) -> [<$sub IterMut>]<'a, T> {
                    [<$sub IterMut>] {
                        iter: self.0.chunks_exact_mut([<$sub:snake _len>])
                    }
                }
            }
        }
    };
    ($cipher:ident < $s:ident >, $sub:ident, $sub_short:ident) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns an iterator over the `", stringify!($sub), "` sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub_short>]<'a>(&'a self, [<$sub_short _len>]: usize) -> [<$sub Iter>]<'a, T> {
                    [<$sub Iter>] {
                        iter: self.0.chunks_exact([<$sub_short _len>])
                    }

                }
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            paste::paste! {
                #[doc = concat!("Returns a mutable iterator over the `", stringify!($sub), "` sub-components of this `", stringify!($cipher), "`.")]
                #[inline]
                pub fn [<iter_ $sub_short _mut>]<'a>(
                    &'a mut self,
                    [<$sub_short _len>]: usize,
                ) -> [<$sub IterMut>]<'a, T> {
                    [<$sub IterMut>] {
                        iter: self.0.chunks_exact_mut([<$sub_short _len>])
                    }
                }
            }
        }
    };
}

macro_rules! impl_basic_operation_single_modulus {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Perform element-wise modular addition `self + rhs`.
            #[inline]
            pub fn add_element_wise<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).add_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
                self
            }

            /// Perform element-wise modular subtraction `self - rhs`.
            #[inline]
            pub fn sub_element_wise<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).sub_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
                self
            }

            /// Performs an element-wise modular addition assignment `self += rhs`.
            #[inline]
            pub fn add_element_wise_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).add_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
            }

            /// Performs an element-wise modular subtraction assignment `self -= rhs`
            #[inline]
            pub fn sub_element_wise_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                ArrayBase(self.as_mut()).sub_element_wise_assign(&ArrayBase(rhs.as_ref()), modulus);
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Performs in-place element-wise modular addition:`result = self + rhs`,
            #[inline]
            pub fn add_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                modulus: M,
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                ArrayBase(self.as_ref()).add_element_wise_to(
                    &ArrayBase(rhs.as_ref()),
                    &mut ArrayBase(result.as_mut()),
                    modulus,
                )
            }

            /// Performs in-place element-wise modular addition:`result = self - rhs`,
            #[inline]
            pub fn sub_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                modulus: M,
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                ArrayBase(self.as_ref()).sub_element_wise_to(
                    &ArrayBase(rhs.as_ref()),
                    &mut ArrayBase(result.as_mut()),
                    modulus,
                )
            }
        }
    };
}

macro_rules! impl_basic_operation_multiple_modulus {
    ($cipher:ident < $s:ident >) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Perform element-wise modular addition `self + rhs`.
            #[inline]
            pub fn add_element_wise<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) -> Self
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                self.add_element_wise_assign(rhs, poly_length, crt_poly_length, moduli);
                self
            }

            /// Perform element-wise modular subtraction `self - rhs`.
            #[inline]
            pub fn sub_element_wise<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) -> Self
            where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                self.sub_element_wise_assign(rhs, poly_length, crt_poly_length, moduli);
                self
            }

            /// Performs an element-wise modular addition assignment `self += rhs`.
            #[inline]
            pub fn add_element_wise_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                izip!(
                    self.0.chunks_exact_mut(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                )
                .for_each(|(x, y)| {
                    izip!(
                        x.chunks_exact_mut(poly_length),
                        y.chunks_exact(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, &modulus)| {
                        ArrayBase(a).add_element_wise_assign(&ArrayBase(b), modulus);
                    });
                });
            }

            /// Performs an element-wise modular subtraction assignment `self -= rhs`.
            #[inline]
            pub fn sub_element_wise_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
            {
                izip!(
                    self.0.chunks_exact_mut(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                )
                .for_each(|(x, y)| {
                    izip!(
                        x.chunks_exact_mut(poly_length),
                        y.chunks_exact(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, &modulus)| {
                        ArrayBase(a).sub_element_wise_assign(&ArrayBase(b), modulus);
                    });
                });
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Performs element-wise modular addition `result = self + rhs`.
            #[inline]
            pub fn add_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                izip!(
                    self.0.chunks_exact(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                    result.0.chunks_exact_mut(crt_poly_length),
                )
                .for_each(|(x, y, z)| {
                    izip!(
                        x.chunks_exact(poly_length),
                        y.chunks_exact(poly_length),
                        z.chunks_exact_mut(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, c, &modulus)| {
                        ArrayBase(a).add_element_wise_to(&ArrayBase(b), &mut ArrayBase(c), modulus);
                    });
                });
            }

            /// Performs element-wise modular subtraction `result = self - rhs`.
            #[inline]
            pub fn sub_element_wise_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                result: &mut $cipher<B>,
                poly_length: usize,
                crt_poly_length: usize,
                moduli: &[M],
            ) where
                M: FieldContext<T>,
                A: RawData<Elem = T> + Data,
                B: RawData<Elem = T> + DataMut,
            {
                izip!(
                    self.0.chunks_exact(crt_poly_length),
                    rhs.0.chunks_exact(crt_poly_length),
                    result.0.chunks_exact_mut(crt_poly_length),
                )
                .for_each(|(x, y, z)| {
                    izip!(
                        x.chunks_exact(poly_length),
                        y.chunks_exact(poly_length),
                        z.chunks_exact_mut(poly_length),
                        moduli
                    )
                    .for_each(|(a, b, c, &modulus)| {
                        ArrayBase(a).sub_element_wise_to(&ArrayBase(b), &mut ArrayBase(c), modulus);
                    });
                });
            }
        }
    };
}

macro_rules! impl_ntt {
    ($cipher:ident < $s:ident >,$ntt_cipher:ident) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Transforms `self` to ntt form.
            #[inline]
            pub fn into_ntt_form<Table>(mut self, ntt_table: &Table) -> $ntt_cipher<S>
            where
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                self.0.chunks_exact_mut(poly_length).for_each(|poly| {
                    ntt_table.transform_slice(poly);
                });
                $ntt_cipher::new(self.0)
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Transforms `self` to ntt form and stores in `result`.
            #[inline]
            pub fn write_ntt_form<Table, A>(&self, result: &mut $ntt_cipher<A>, ntt_table: &Table)
            where
                A: RawData<Elem = T> + DataMut,
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                result.0.copy_from_slice(self.as_ref());
                result.0.chunks_exact_mut(poly_length).for_each(|poly| {
                    ntt_table.transform_slice(poly);
                });
            }
        }
    };
}

macro_rules! impl_intt {
    ($ntt_cipher:ident < $s:ident >,$cipher:ident) => {
        impl<$s, T> $ntt_cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form.
            #[inline]
            pub fn into_coeff_form<Table>(mut self, ntt_table: &Table) -> $cipher<S>
            where
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                self.0.chunks_exact_mut(poly_length).for_each(|poly| {
                    ntt_table.inverse_transform_slice(poly);
                });
                $cipher::new(self.0)
            }
        }

        impl<$s, T> $ntt_cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form and stores in `result`.
            #[inline]
            pub fn write_coeff_form<Table, A>(&self, result: &mut $cipher<A>, ntt_table: &Table)
            where
                A: RawData<Elem = T> + DataMut,
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length();
                result.0.copy_from_slice(self.as_ref());
                result.0.chunks_exact_mut(poly_length).for_each(|values| {
                    ntt_table.inverse_transform_slice(values);
                });
            }
        }
    };
}

macro_rules! impl_crt_ntt {
    ($cipher:ident < $s:ident >,$ntt_cipher:ident) => {
        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Transforms `self` to ntt form.
            #[inline]
            pub fn into_ntt_form<Table>(self, table: &Table) -> $ntt_cipher<$s>
            where
                Table: DcrtTable<ValueT = T>,
            {
                let crt_poly_length = table.crt_poly_length();
                let Self(mut data) = self;
                data.chunks_exact_mut(crt_poly_length).for_each(|crt_poly| {
                    table.transform_slice(crt_poly);
                });
                $ntt_cipher::new(data)
            }
        }

        impl<$s, T> $cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Transforms `self` to ntt form and stores in `result`.
            #[inline]
            pub fn write_ntt_form<Table, A>(&self, result: &mut $ntt_cipher<A>, table: &Table)
            where
                Table: DcrtTable<ValueT = T>,
                A: RawData<Elem = T> + DataMut,
            {
                let crt_poly_length = table.crt_poly_length();
                result.0.copy_from_slice(self.as_ref());
                result
                    .0
                    .chunks_exact_mut(crt_poly_length)
                    .for_each(|crt_poly| {
                        table.transform_slice(crt_poly);
                    });
            }
        }
    };
}

// --------------------------------------------------------------------------
// Fourier-domain macros (Complex64 element, no FheUint requirement)
// --------------------------------------------------------------------------

/// Generates `{Cipher}Iter<'a>` and `{Cipher}IterMut<'a>` chunked iterator
/// types for a Fourier ciphertext over `Complex64` elements.
macro_rules! impl_fourier_iters {
    ($cipher:ident) => {
        paste::paste! {
            #[doc = concat!(
                "Immutable chunked iterator over [`",
                stringify!($cipher),
                "`] ciphertexts."
            )]
            #[derive(Debug, Clone)]
            pub struct [<$cipher Iter>]<'a> {
                iter: core::slice::ChunksExact<'a, num_complex::Complex64>,
            }

            impl<'a> [<$cipher Iter>]<'a> {
                #[doc = concat!(
                    "Creates an iterator yielding `",
                    stringify!($cipher),
                    "` chunks of `chunk_len` elements each."
                )]
                #[inline]
                pub fn new(data: &'a [num_complex::Complex64], chunk_len: usize) -> Self {
                    Self {
                        iter: data.chunks_exact(chunk_len),
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
            }

            impl<'a> core::iter::FusedIterator for [<$cipher Iter>]<'a> {}
            impl<'a> core::iter::ExactSizeIterator for [<$cipher Iter>]<'a> {}
        }

        paste::paste! {
            #[doc = concat!(
                "Mutable chunked iterator over [`",
                stringify!($cipher),
                "`] ciphertexts."
            )]
            #[derive(Debug)]
            pub struct [<$cipher IterMut>]<'a> {
                iter: core::slice::ChunksExactMut<'a, num_complex::Complex64>,
            }

            impl<'a> [<$cipher IterMut>]<'a> {
                #[doc = concat!(
                    "Creates a mutable iterator yielding `",
                    stringify!($cipher),
                    "` chunks of `chunk_len` elements each."
                )]
                #[inline]
                pub fn new(data: &'a mut [num_complex::Complex64], chunk_len: usize) -> Self {
                    Self {
                        iter: data.chunks_exact_mut(chunk_len),
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
            }

            impl<'a> core::iter::FusedIterator for [<$cipher IterMut>]<'a> {}
            impl<'a> core::iter::ExactSizeIterator for [<$cipher IterMut>]<'a> {}
        }
    };
}

/// Generates `{Cipher}Owned` type alias and core methods (`new`, `zero`,
/// `set_zero`, `as_ref`, `as_mut`, `byte_count`) for a Fourier ciphertext.
macro_rules! impl_fourier_core {
    ($cipher:ident) => {
        paste::paste! {
            #[doc = concat!("Owned [`", stringify!($cipher), "`] backed by a [`Vec`].")]
            pub type [<$cipher Owned>] = $cipher<Vec<num_complex::Complex64>>;
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64>,
        {
            #[doc = concat!("Creates a new [`", stringify!($cipher), "`].")]
            #[inline]
            pub fn new(data: S) -> Self {
                Self(data)
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataOwned,
        {
            paste::paste! {
                #[doc = concat!("Creates a zero-initialized [`", stringify!($cipher), "`].")]
                #[inline]
                pub fn zero([< $cipher:snake _len >]: usize) -> Self {
                    Self(S::from_vec(vec![
                        num_complex::Complex64::new(0.0, 0.0);
                        [< $cipher:snake _len >]
                    ]))
                }
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
        {
            /// Sets all elements to zero.
            #[inline]
            pub fn set_zero(&mut self) {
                self.0.fill(num_complex::Complex64::new(0.0, 0.0));
            }
        }

        impl<S> $cipher<S>
        where
            S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
        {
            /// Returns the total byte count.
            #[inline]
            pub fn byte_count(&self) -> usize {
                self.0.len() * core::mem::size_of::<num_complex::Complex64>()
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
/// - `$sub_iter` / `$sub_iter_mut`: the sub-component's iterator types
/// - `$method`: the method name prefix (e.g., `fourier_poly` → `iter_fourier_poly`)
macro_rules! impl_fourier_iter_sub {
    ($cipher:ident, $sub_iter:ident, $sub_iter_mut:ident, $method:ident) => {
        paste::paste! {
            impl<S> $cipher<S>
            where
                S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::Data,
            {
                #[doc = concat!(
                    "Returns an iterator over the [`",
                    stringify!($sub_iter),
                    "`] sub-components."
                )]
                #[inline]
                pub fn [<iter_ $method>](
                    &self,
                    sub_len: usize,
                ) -> $sub_iter<'_> {
                    $sub_iter::new(self.as_ref(), sub_len)
                }
            }

            impl<S> $cipher<S>
            where
                S: primus_data::RawData<Elem = num_complex::Complex64> + primus_data::DataMut,
            {
                #[doc = concat!(
                    "Returns a mutable iterator over the [`",
                    stringify!($sub_iter_mut),
                    "`] sub-components."
                )]
                #[inline]
                pub fn [<iter_ $method _mut>](
                    &mut self,
                    sub_len: usize,
                ) -> $sub_iter_mut<'_> {
                    $sub_iter_mut::new(self.0.as_mut_slice(), sub_len)
                }
            }
        }
    };
}

macro_rules! impl_crt_intt {
    ($ntt_cipher:ident < $s:ident >,$cipher:ident) => {
        impl<$s, T> $ntt_cipher<$s>
        where
            $s: RawData<Elem = T> + DataMut,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form.
            #[inline]
            pub fn into_coeff_form<Table>(self, table: &Table) -> $cipher<$s>
            where
                Table: DcrtTable<ValueT = T>,
            {
                let crt_poly_length = table.crt_poly_length();
                let Self(mut data) = self;
                data.chunks_exact_mut(crt_poly_length).for_each(|crt_poly| {
                    table.inverse_transform_slice(crt_poly);
                });
                $cipher::new(data)
            }
        }

        impl<$s, T> $ntt_cipher<$s>
        where
            $s: RawData<Elem = T> + Data,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form and stores in `result`.
            #[inline]
            pub fn write_coeff_form<Table, A>(&self, result: &mut $cipher<A>, table: &Table)
            where
                Table: DcrtTable<ValueT = T>,
                A: RawData<Elem = T> + DataMut,
            {
                let crt_poly_length = table.crt_poly_length();
                result.0.copy_from_slice(self.as_ref());
                result
                    .0
                    .chunks_exact_mut(crt_poly_length)
                    .for_each(|crt_poly| {
                        table.inverse_transform_slice(crt_poly);
                    });
            }
        }
    };
}
