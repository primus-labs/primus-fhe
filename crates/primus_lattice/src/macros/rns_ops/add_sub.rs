//! RNS add/sub arithmetic.

macro_rules! impl_basic_operation_multiple_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Consumes `self` and adds `rhs`, reusing storage.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus operation's input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[must_use]
            #[inline]
            pub fn add<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) -> Self
            where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                self.add_assign(rhs, poly_length, rns_poly_len, moduli);
                self
            }

            /// Performs `self += rhs` in place.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus operation's input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn add_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "RNS operand length mismatch"
                );
                for (lhs, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(rns_poly_len)
                    .zip(rhs.as_ref().chunks_exact(rns_poly_len))
                {
                    for (lhs, rhs, &modulus) in itertools::izip!(
                        lhs.chunks_exact_mut(poly_length),
                        rhs.chunks_exact(poly_length),
                        moduli
                    ) {
                        modulus.reduce_add_slice_assign(lhs, rhs);
                    }
                }
            }

            /// Consumes `self` and subtracts `rhs`, reusing storage.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus operation's input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[must_use]
            #[inline]
            pub fn sub<M, A>(
                mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) -> Self
            where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                self.sub_assign(rhs, poly_length, rns_poly_len, moduli);
                self
            }

            /// Performs `self -= rhs` in place.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus operation's input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn sub_assign<M, A>(
                &mut self,
                rhs: &$cipher<A>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "RNS operand length mismatch"
                );
                for (lhs, rhs) in self
                    .as_mut()
                    .chunks_exact_mut(rns_poly_len)
                    .zip(rhs.as_ref().chunks_exact(rns_poly_len))
                {
                    for (lhs, rhs, &modulus) in itertools::izip!(
                        lhs.chunks_exact_mut(poly_length),
                        rhs.chunks_exact(poly_length),
                        moduli
                    ) {
                        modulus.reduce_sub_slice_assign(lhs, rhs);
                    }
                }
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = self + rhs`, overwriting existing output.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus operation's input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn add_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                output: &mut $cipher<B>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: primus_data::Data<Elem = T>,
                B: primus_data::DataMut<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "RNS operand length mismatch"
                );
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "RNS output length mismatch"
                );
                for (lhs, rhs, output) in itertools::izip!(
                    self.as_ref().chunks_exact(rns_poly_len),
                    rhs.as_ref().chunks_exact(rns_poly_len),
                    output.as_mut().chunks_exact_mut(rns_poly_len)
                ) {
                    for (lhs, rhs, output, &modulus) in itertools::izip!(
                        lhs.chunks_exact(poly_length),
                        rhs.chunks_exact(poly_length),
                        output.chunks_exact_mut(poly_length),
                        moduli
                    ) {
                        modulus.reduce_add_slice_to(lhs, rhs, output);
                    }
                }
            }

            /// Writes `output = self - rhs`, overwriting existing output.
            ///
            /// # Correctness
            ///
            /// Components are stored consecutively; each contains one length-`poly_length`
            /// block per modulus, in `moduli` order. `poly_length` and `moduli.len()`
            /// must be nonzero, `rns_poly_len = poly_length * moduli.len()`, and
            /// ciphertext lengths must be multiples of `rns_poly_len`.
            /// All operands must have equal lengths, the same ordered modulus base,
            /// and the same coefficient or NTT representation.
            /// Values must satisfy each modulus operation's input range.
            ///
            /// # Panics
            ///
            /// Panics when a zero chunk length is used. Other layout requirements
            /// are caller obligations; debug assertions do not provide release validation.
            #[inline]
            pub fn sub_to<M, A, B>(
                &self,
                rhs: &$cipher<A>,
                output: &mut $cipher<B>,
                poly_length: usize,
                rns_poly_len: usize,
                moduli: &[M],
            ) where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: primus_data::Data<Elem = T>,
                B: primus_data::DataMut<Elem = T>,
            {
                debug_assert_eq!(
                    self.as_ref().len(),
                    rhs.as_ref().len(),
                    "RNS operand length mismatch"
                );
                debug_assert_eq!(
                    self.as_ref().len(),
                    output.as_ref().len(),
                    "RNS output length mismatch"
                );
                for (lhs, rhs, output) in itertools::izip!(
                    self.as_ref().chunks_exact(rns_poly_len),
                    rhs.as_ref().chunks_exact(rns_poly_len),
                    output.as_mut().chunks_exact_mut(rns_poly_len)
                ) {
                    for (lhs, rhs, output, &modulus) in itertools::izip!(
                        lhs.chunks_exact(poly_length),
                        rhs.chunks_exact(poly_length),
                        output.chunks_exact_mut(poly_length),
                        moduli
                    ) {
                        modulus.reduce_sub_slice_to(lhs, rhs, output);
                    }
                }
            }
        }
    };
}
