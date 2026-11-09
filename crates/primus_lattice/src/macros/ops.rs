//! Single-modulus ciphertext arithmetic, grouped by supported operation.

macro_rules! impl_basic_operation_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: DataMut<Elem = T>,
            T: FheUint,
        {
            /// Consumes `self` and adds `rhs`, reusing the backing storage.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[must_use]
            #[inline]
            pub fn add<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: Data<Elem = T>,
            {
                modulus.reduce_add_slice_assign(self.as_mut(), rhs.as_ref());
                self
            }

            /// Consumes `self` and subtracts `rhs`, reusing the backing storage.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[must_use]
            #[inline]
            pub fn sub<M, A>(mut self, rhs: &$cipher<A>, modulus: M) -> Self
            where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: Data<Elem = T>,
            {
                modulus.reduce_sub_slice_assign(self.as_mut(), rhs.as_ref());
                self
            }

            /// Performs an element-wise modular addition assignment `self += rhs`.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn add_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: Data<Elem = T>,
            {
                modulus.reduce_add_slice_assign(self.as_mut(), rhs.as_ref());
            }

            /// Performs an element-wise modular subtraction assignment `self -= rhs`
            ///
            /// # Correctness
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn sub_assign<M, A>(&mut self, rhs: &$cipher<A>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: Data<Elem = T>,
            {
                modulus.reduce_sub_slice_assign(self.as_mut(), rhs.as_ref());
            }
        }

        impl<S, T> $cipher<S>
        where
            S: Data<Elem = T>,
            T: FheUint,
        {
            /// Writes the element-wise modular sum `output = self + rhs`.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn add_to<M, A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceAddSlice<T>,
                A: Data<Elem = T>,
                B: DataMut<Elem = T>,
            {
                modulus.reduce_add_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
            }

            /// Writes the element-wise modular difference `output = self - rhs`.
            ///
            /// # Correctness
            ///
            /// All ciphertexts must have the same layout and length. Coefficients must
            /// satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn sub_to<M, A, B>(&self, rhs: &$cipher<A>, output: &mut $cipher<B>, modulus: M)
            where
                M: Copy + primus_reduce::ReduceSubSlice<T>,
                A: Data<Elem = T>,
                B: DataMut<Elem = T>,
            {
                modulus.reduce_sub_slice_to(self.as_ref(), rhs.as_ref(), output.as_mut());
            }
        }
    };
}

// Single-modulus operations shared without imposing a polynomial layout.
macro_rules! impl_neg_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Negates every ciphertext component modulo `modulus` in place.
            ///
            /// # Correctness
            ///
            /// Coefficients must satisfy the input range required by `modulus`.
            #[inline]
            pub fn neg_assign<M>(&mut self, modulus: M)
            where
                M: primus_reduce::ReduceNegSlice<T>,
            {
                modulus.reduce_neg_slice_assign(self.as_mut());
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = -self` into existing storage.
            ///
            /// # Correctness
            ///
            /// Input and output must have the same layout and length.
            /// Coefficients must satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn neg_to<M, A>(&self, output: &mut $cipher<A>, modulus: M)
            where
                M: primus_reduce::ReduceNegSlice<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                modulus.reduce_neg_slice_to(self.as_ref(), output.as_mut());
            }
        }
    };
}

macro_rules! impl_mul_scalar_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every ciphertext component by `scalar` in place.
            ///
            /// # Correctness
            ///
            /// Coefficients and `scalar` must satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
            where
                M: primus_reduce::ReduceMulSlice<T>,
            {
                modulus.reduce_mul_scalar_slice_assign(self.as_mut(), scalar);
            }

            /// Accumulates `self += rhs * scalar` without clearing `self` or allocating.
            ///
            /// # Correctness
            ///
            /// Both ciphertexts must have the same length, layout, representation,
            /// and compatible key semantics. Gadget bases and level/row order must
            /// match. Input, accumulator, and scalar must be canonical residues;
            /// results are canonical residues under the same modulus.
            #[inline]
            pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &$cipher<A>, scalar: T, modulus: M)
            where
                M: primus_reduce::ReduceMulAddSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                modulus.reduce_add_mul_scalar_slice_assign(self.as_mut(), rhs.as_ref(), scalar);
            }

            /// Accumulates `self -= rhs * scalar` without clearing `self` or allocating.
            ///
            /// # Correctness
            ///
            /// Both ciphertexts must have the same length, layout, representation,
            /// and compatible key semantics. Gadget bases and level/row order must
            /// match. Input, accumulator, and scalar must be canonical residues;
            /// results are canonical residues under the same modulus.
            #[inline]
            pub fn sub_mul_scalar_assign<M, A>(&mut self, rhs: &$cipher<A>, scalar: T, modulus: M)
            where
                M: Copy
                    + primus_reduce::ReduceNeg<T, Output = T>
                    + primus_reduce::ReduceMulAddSlice<T>,
                A: primus_data::Data<Elem = T>,
            {
                // Negate the scalar once to reuse the scalar FMA kernel, including SIMD.
                let neg_scalar = modulus.reduce_neg(scalar);
                modulus.reduce_add_mul_scalar_slice_assign(self.as_mut(), rhs.as_ref(), neg_scalar);
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = self * scalar` into existing storage.
            ///
            /// # Correctness
            ///
            /// Input and output must have the same layout and length.
            /// Coefficients and `scalar` must satisfy the input ranges required by `modulus`.
            #[inline]
            pub fn mul_scalar_to<M, A>(&self, scalar: T, output: &mut $cipher<A>, modulus: M)
            where
                M: primus_reduce::ReduceMulSlice<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                modulus.reduce_mul_scalar_slice_to(self.as_ref(), scalar, output.as_mut());
            }
        }
    };
}

macro_rules! impl_mul_factor_single_modulus {
    ($cipher:ident) => {
        impl<S, T> $cipher<S>
        where
            S: primus_data::DataMut<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Multiplies every ciphertext component by a precomputed `factor` in place.
            ///
            /// # Correctness
            ///
            /// The factor must be prepared for `modulus`; stored values must be in
            /// `[0, modulus)`. Every component, including all gadget
            /// levels and rows, is scaled by the same factor without changing layout
            /// or coefficient/NTT representation. Outputs are reduced modulo `modulus`.
            #[inline]
            pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
            where
                F: primus_factor::FactorSliceOps<T>,
            {
                factor.factor_mul_slice_assign(self.as_mut(), modulus);
            }

            /// Accumulates `self += rhs * factor` without clearing `self` or allocating.
            ///
            /// # Correctness
            ///
            /// Both ciphertexts must have the same length, layout, representation,
            /// and compatible key semantics. Gadget bases and level/row order must
            /// match. The same factor applies to every component.
            /// The factor must be prepared for `modulus`; input and accumulator
            /// values must be in `[0, modulus)`. Results remain in that range.
            #[inline]
            pub fn add_mul_factor_assign<F, A>(&mut self, rhs: &$cipher<A>, factor: F, modulus: T)
            where
                F: primus_factor::FactorSliceOps<T>,
                A: primus_data::Data<Elem = T>,
            {
                factor.add_factor_mul_slice_assign(self.as_mut(), rhs.as_ref(), modulus);
            }

            /// Accumulates `self -= rhs * factor` without clearing `self` or allocating.
            ///
            /// # Correctness
            ///
            /// Both ciphertexts must have the same length, layout, representation,
            /// and compatible key semantics. Gadget bases and level/row order must
            /// match. The same factor applies to every component.
            /// The factor must be prepared for `modulus`; input and accumulator
            /// values must be in `[0, modulus)`. Results remain in that range.
            #[inline]
            pub fn sub_mul_factor_assign<F, A>(&mut self, rhs: &$cipher<A>, factor: F, modulus: T)
            where
                F: primus_factor::FactorSliceOps<T>,
                A: primus_data::Data<Elem = T>,
            {
                factor.sub_factor_mul_slice_assign(self.as_mut(), rhs.as_ref(), modulus);
            }
        }
        impl<S, T> $cipher<S>
        where
            S: primus_data::Data<Elem = T>,
            T: primus_integer::FheUint,
        {
            /// Writes `output = self * factor`, overwriting existing output storage.
            ///
            /// # Correctness
            ///
            /// Input and output must have the same layout and length. The factor
            /// must be prepared for `modulus`; stored values must be in `[0, modulus)`.
            /// Every component, including all gadget levels and rows, is
            /// scaled by the same factor without changing coefficient/NTT
            /// representation. Outputs are reduced modulo `modulus`.
            #[inline]
            pub fn mul_factor_to<F, A>(&self, factor: F, output: &mut $cipher<A>, modulus: T)
            where
                F: primus_factor::FactorSliceOps<T>,
                A: primus_data::DataMut<Elem = T>,
            {
                factor.factor_mul_slice_to(self.as_ref(), output.as_mut(), modulus);
            }
        }
    };
}
