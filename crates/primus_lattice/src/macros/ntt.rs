//! NTT and CRT ↔ DCRT domain transforms.
//!
//! Generates `into_ntt_form` / `write_ntt_form` and `into_coeff_form` /
//! `write_coeff_form` for both single-modulus (NTT) and multi-modulus
//! (CRT ↔ DCRT) representations.

macro_rules! impl_ntt {
    ($cipher:ident,$ntt_cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete polynomials of `ntt_table.poly_length().get()`
            /// elements. The NTT table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            #[inline]
            pub fn into_ntt_form<Table>(mut self, ntt_table: &Table) -> $ntt_cipher<S>
            where
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length().get();
                primus_poly::PolynomialIterMut::new(self.as_mut(), poly_length).for_each(
                    |mut poly| {
                        ntt_table.transform_slice(poly.as_mut());
                    },
                );
                $ntt_cipher::new(self.0)
            }
        }

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form and stores in `output`.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete polynomials of `ntt_table.poly_length().get()`
            /// elements. The NTT table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            /// Output has the same layout and element count as the input and is overwritten.
            ///
            /// # Panics
            ///
            /// Panics if input and output storage lengths differ.
            #[inline]
            pub fn write_ntt_form<Table, A>(&self, output: &mut $ntt_cipher<A>, ntt_table: &Table)
            where
                A: DataMut<Elem = T>,
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length().get();
                output.0.copy_from_slice(self.as_ref());
                primus_poly::PolynomialIterMut::new(output.as_mut(), poly_length).for_each(
                    |mut poly| {
                        ntt_table.transform_slice(poly.as_mut());
                    },
                );
            }
        }
    };
}

macro_rules! impl_intt {
    ($ntt_cipher:ident,$cipher:ident) => {
        impl<S, T> $ntt_cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete polynomials of `ntt_table.poly_length().get()`
            /// elements. The NTT table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            #[inline]
            pub fn into_coeff_form<Table>(mut self, ntt_table: &Table) -> $cipher<S>
            where
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length().get();
                primus_poly::NttPolynomialIterMut::new(self.as_mut(), poly_length).for_each(
                    |mut poly| {
                        ntt_table.inverse_transform_slice(poly.as_mut());
                    },
                );
                $cipher::new(self.0)
            }
        }

        impl<S, T> $ntt_cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form and stores in `output`.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete polynomials of `ntt_table.poly_length().get()`
            /// elements. The NTT table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            /// Output has the same layout and element count as the input and is overwritten.
            ///
            /// # Panics
            ///
            /// Panics if input and output storage lengths differ.
            #[inline]
            pub fn write_coeff_form<Table, A>(&self, output: &mut $cipher<A>, ntt_table: &Table)
            where
                A: DataMut<Elem = T>,
                Table: NttTable<ValueT = T>,
            {
                let poly_length = ntt_table.poly_length().get();
                output.0.copy_from_slice(self.as_ref());
                primus_poly::NttPolynomialIterMut::new(output.as_mut(), poly_length).for_each(
                    |mut values| {
                        ntt_table.inverse_transform_slice(values.as_mut());
                    },
                );
            }
        }
    };
}

#[cfg(feature = "rns")]
macro_rules! impl_crt_ntt {
    ($cipher:ident,$ntt_cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete RNS polynomials of `table.rns_poly_len()`
            /// elements. Each consists of one coefficient/evaluation block per
            /// modulus in the table's modulus order. The table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            #[inline]
            pub fn into_ntt_form<Table>(
                self,
                table: &primus_ntt::DcrtTable<Table>,
            ) -> $ntt_cipher<S>
            where
                Table: primus_ntt::NttTable<ValueT = T>,
            {
                let rns_poly_len = table.rns_poly_len();
                let Self(mut data) = self;
                primus_poly::CrtPolynomialIterMut::new(data.as_mut_slice(), rns_poly_len).for_each(
                    |mut crt_poly| {
                        table.transform_slice(crt_poly.as_mut());
                    },
                );
                $ntt_cipher::new(data)
            }
        }

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to ntt form and stores in `output`.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete RNS polynomials of `table.rns_poly_len()`
            /// elements. Each consists of one coefficient/evaluation block per
            /// modulus in the table's modulus order. The table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            /// Output has the same layout and element count as the input and is overwritten.
            ///
            /// # Panics
            ///
            /// Panics if input and output storage lengths differ.
            #[inline]
            pub fn write_ntt_form<Table, A>(
                &self,
                output: &mut $ntt_cipher<A>,
                table: &primus_ntt::DcrtTable<Table>,
            ) where
                Table: primus_ntt::NttTable<ValueT = T>,
                A: DataMut<Elem = T>,
            {
                let rns_poly_len = table.rns_poly_len();
                output.0.copy_from_slice(self.as_ref());
                primus_poly::CrtPolynomialIterMut::new(output.as_mut(), rns_poly_len).for_each(
                    |mut crt_poly| {
                        table.transform_slice(crt_poly.as_mut());
                    },
                );
            }
        }
    };
}

#[cfg(feature = "rns")]
macro_rules! impl_crt_intt {
    ($ntt_cipher:ident,$cipher:ident) => {
        impl<S, T> $ntt_cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete RNS polynomials of `table.rns_poly_len()`
            /// elements. Each consists of one coefficient/evaluation block per
            /// modulus in the table's modulus order. The table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            #[inline]
            pub fn into_coeff_form<Table>(self, table: &primus_ntt::DcrtTable<Table>) -> $cipher<S>
            where
                Table: primus_ntt::NttTable<ValueT = T>,
            {
                let rns_poly_len = table.rns_poly_len();
                let Self(mut data) = self;
                primus_poly::DcrtPolynomialIterMut::new(data.as_mut_slice(), rns_poly_len)
                    .for_each(|mut dcrt_poly| {
                        table.inverse_transform_slice(dcrt_poly.as_mut());
                    });
                $cipher::new(data)
            }
        }

        impl<S, T> $ntt_cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Transforms `self` to coefficient form and stores in `output`.
            ///
            /// # Correctness
            ///
            /// Storage must contain complete RNS polynomials of `table.rns_poly_len()`
            /// elements. Each consists of one coefficient/evaluation block per
            /// modulus in the table's modulus order. The table must match the
            /// ciphertext modulus and transform convention, and values must satisfy
            /// the corresponding transform's input range. Inverse transforms require
            /// the same evaluation order as the forward transform. Complete blocks are
            /// assumed; incomplete trailing blocks are not transformed. Empty batches are valid.
            /// Output has the same layout and element count as the input and is overwritten.
            ///
            /// # Panics
            ///
            /// Panics if input and output storage lengths differ.
            #[inline]
            pub fn write_coeff_form<Table, A>(
                &self,
                output: &mut $cipher<A>,
                table: &primus_ntt::DcrtTable<Table>,
            ) where
                Table: primus_ntt::NttTable<ValueT = T>,
                A: DataMut<Elem = T>,
            {
                let rns_poly_len = table.rns_poly_len();
                output.0.copy_from_slice(self.as_ref());
                primus_poly::DcrtPolynomialIterMut::new(output.as_mut(), rns_poly_len).for_each(
                    |mut dcrt_poly| {
                        table.inverse_transform_slice(dcrt_poly.as_mut());
                    },
                );
            }
        }
    };
}
