//! Body operations on already encoded plaintexts, without encoding or scale conversion.

macro_rules! impl_plaintext_single_modulus {
    ($cipher:ident, $poly:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Adds an already encoded plaintext to the body, leaving the mask unchanged.
            ///
            /// # Correctness
            ///
            /// `plaintext` must contain one complete nonempty polynomial in this
            /// ciphertext's representation, modulus domain and plaintext scale.
            /// Storage must contain complete mask polynomials followed by one body.
            /// No encoding, rounding, random
            /// sampling or allocation is performed. The caller maintains the layout.
            /// Input residues must be canonical; output residues remain canonical.
            ///
            /// # Panics
            ///
            /// Panics if the plaintext storage is longer than the ciphertext storage.
            #[inline]
            pub fn add_plaintext_assign<M, A>(
                &mut self,
                plaintext: &primus_poly::$poly<A>,
                modulus: M,
            ) where
                A: primus_data::Data<Elem = T>,
                M: Copy + primus_reduce::ReduceAddSlice<T>,
            {
                let body_len = plaintext.as_ref().len();
                let len = self.as_ref().len();
                let body = &mut self.as_mut()[len - body_len..];
                modulus.reduce_add_slice_assign(body, plaintext.as_ref());
            }

            /// Subtracts an already encoded plaintext from the body, leaving the mask unchanged.
            ///
            /// # Correctness
            ///
            /// `plaintext` must contain one complete nonempty polynomial in this
            /// ciphertext's representation, modulus domain and plaintext scale.
            /// Storage must contain complete mask polynomials followed by one body.
            /// No encoding, rounding, random
            /// sampling or allocation is performed. The caller maintains the layout.
            /// Input residues must be canonical; output residues remain canonical.
            ///
            /// # Panics
            ///
            /// Panics if the plaintext storage is longer than the ciphertext storage.
            #[inline]
            pub fn sub_plaintext_assign<M, A>(
                &mut self,
                plaintext: &primus_poly::$poly<A>,
                modulus: M,
            ) where
                A: primus_data::Data<Elem = T>,
                M: Copy + primus_reduce::ReduceSubSlice<T>,
            {
                let body_len = plaintext.as_ref().len();
                let len = self.as_ref().len();
                let body = &mut self.as_mut()[len - body_len..];
                modulus.reduce_sub_slice_assign(body, plaintext.as_ref());
            }

            /// Overwrites this ciphertext with a trivial encryption: zero mask and encoded body.
            ///
            /// # Correctness
            ///
            /// `plaintext` must contain one complete nonempty polynomial in this
            /// ciphertext's representation, modulus domain and plaintext scale.
            /// Storage must contain complete mask polynomials followed by one body.
            /// No encoding, rounding, random
            /// sampling or allocation is performed. The caller maintains the layout.
            /// Input residues must be canonical; output residues remain canonical.
            ///
            /// # Panics
            ///
            /// Panics if the plaintext storage is longer than the ciphertext storage.
            #[inline]
            pub fn set_trivial<A>(&mut self, plaintext: &primus_poly::$poly<A>)
            where
                A: primus_data::Data<Elem = T>,
            {
                let body_len = plaintext.as_ref().len();
                let len = self.as_ref().len();
                let (mask, body) = self.as_mut().split_at_mut(len - body_len);
                mask.fill(T::ZERO);
                body.copy_from_slice(plaintext.as_ref());
            }
        }
    };
}

#[cfg(feature = "rns")]
macro_rules! impl_plaintext_multiple_modulus {
    ($cipher:ident, $poly:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Adds an already encoded plaintext to the body, leaving the mask unchanged.
            ///
            /// # Correctness
            ///
            /// `plaintext` must contain one complete nonempty polynomial in this
            /// ciphertext's representation, modulus domain and plaintext scale.
            /// Storage must contain complete mask polynomials followed by one body.
            /// No encoding, rounding, random
            /// sampling or allocation is performed. The caller maintains the layout.
            /// Input residues must be canonical; output residues remain canonical.
            /// RNS polynomials contain one block per modulus in the same basis order.
            /// The basis must be nonempty and `plaintext.as_ref().len() = poly_length * moduli.len()`.
            ///
            /// # Panics
            ///
            /// Panics if the plaintext storage is longer than the ciphertext storage.
            #[inline]
            pub fn add_plaintext_assign<M, A>(
                &mut self,
                plaintext: &primus_poly::$poly<A>,
                poly_length: usize,
                moduli: &[M],
            ) where
                A: primus_data::Data<Elem = T>,
                M: Copy + primus_reduce::ReduceAddSlice<T>,
            {
                let body_len = plaintext.as_ref().len();
                let len = self.as_ref().len();
                let body = &mut self.as_mut()[len - body_len..];
                for (body, input, &modulus) in itertools::izip!(
                    body.chunks_exact_mut(poly_length),
                    plaintext.as_ref().chunks_exact(poly_length),
                    moduli
                ) {
                    modulus.reduce_add_slice_assign(body, input);
                }
            }

            /// Subtracts an already encoded plaintext from the body, leaving the mask unchanged.
            ///
            /// # Correctness
            ///
            /// `plaintext` must contain one complete nonempty polynomial in this
            /// ciphertext's representation, modulus domain and plaintext scale.
            /// Storage must contain complete mask polynomials followed by one body.
            /// No encoding, rounding, random
            /// sampling or allocation is performed. The caller maintains the layout.
            /// Input residues must be canonical; output residues remain canonical.
            /// RNS polynomials contain one block per modulus in the same basis order.
            /// The basis must be nonempty and `plaintext.as_ref().len() = poly_length * moduli.len()`.
            ///
            /// # Panics
            ///
            /// Panics if the plaintext storage is longer than the ciphertext storage.
            #[inline]
            pub fn sub_plaintext_assign<M, A>(
                &mut self,
                plaintext: &primus_poly::$poly<A>,
                poly_length: usize,
                moduli: &[M],
            ) where
                A: primus_data::Data<Elem = T>,
                M: Copy + primus_reduce::ReduceSubSlice<T>,
            {
                let body_len = plaintext.as_ref().len();
                let len = self.as_ref().len();
                let body = &mut self.as_mut()[len - body_len..];
                for (body, input, &modulus) in itertools::izip!(
                    body.chunks_exact_mut(poly_length),
                    plaintext.as_ref().chunks_exact(poly_length),
                    moduli
                ) {
                    modulus.reduce_sub_slice_assign(body, input);
                }
            }

            /// Overwrites this ciphertext with a trivial encryption: zero mask and encoded body.
            ///
            /// # Correctness
            ///
            /// `plaintext` must contain one complete nonempty polynomial in this
            /// ciphertext's representation, modulus domain and plaintext scale.
            /// Storage must contain complete mask polynomials followed by one body.
            /// No encoding, rounding, random
            /// sampling or allocation is performed. The caller maintains the layout.
            /// Input residues must be canonical; output residues remain canonical.
            /// RNS polynomials contain one block per modulus in the same basis order.
            ///
            /// # Panics
            ///
            /// Panics if the plaintext storage is longer than the ciphertext storage.
            #[inline]
            pub fn set_trivial<A>(&mut self, plaintext: &primus_poly::$poly<A>)
            where
                A: primus_data::Data<Elem = T>,
            {
                let body_len = plaintext.as_ref().len();
                let len = self.as_ref().len();
                let (mask, body) = self.as_mut().split_at_mut(len - body_len);
                mask.fill(T::ZERO);
                body.copy_from_slice(plaintext.as_ref());
            }
        }
    };
}
