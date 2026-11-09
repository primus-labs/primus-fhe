use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

pub(crate) fn slice_ops(name: &Ident, modulus: &TokenStream, ty: &syn::Path) -> TokenStream {
    let kernels = super::slice_kernels::kernel_module();
    let mul_generics = super::slice_kernels::multiplication_generics(ty);
    // SIMD dot products have dedicated Barrett entry points. Iterator inputs
    // keep the scalar implementation because they have no contiguous layout.
    let (dot_product, signed_dot_product) = if cfg!(feature = "simd") {
        (
            quote!(::primus_modulus::barrett_simd_reduce_dot_product),
            quote!(::primus_modulus::barrett_simd_reduce_dot_product_signed),
        )
    } else {
        (
            quote!(::primus_modulus::common::compact::slice::reduce_dot_product),
            quote!(::primus_modulus::common::compact::slice::reduce_dot_product_signed),
        )
    };

    quote! {
        // ReduceOnceSlice
        impl ::primus_modulus::reduce::ReduceOnceSlice<#ty> for #name {
            #[inline]
            fn reduce_once_slice_assign(self, values: &mut [#ty]) {
                #kernels::reduce_once_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_once_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                #kernels::reduce_once_slice_to(#modulus, input, output);
            }
        }
        // ReduceNegSlice
        impl ::primus_modulus::reduce::ReduceNegSlice<#ty> for #name {
            #[inline]
            fn reduce_neg_slice_assign(self, values: &mut [#ty]) {
                #kernels::reduce_neg_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_neg_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                #kernels::reduce_neg_slice_to(#modulus, input, output);
            }
        }
        // ReduceAddSlice
        impl ::primus_modulus::reduce::ReduceAddSlice<#ty> for #name {
            #[inline]
            fn reduce_add_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                #kernels::reduce_add_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn reduce_add_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                #kernels::reduce_add_slice_to(#modulus, a, b, output);
            }
        }
        // ReduceSubSlice
        impl ::primus_modulus::reduce::ReduceSubSlice<#ty> for #name {
            #[inline]
            fn reduce_sub_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                #kernels::reduce_sub_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn reduce_sub_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                #kernels::reduce_sub_slice_to(#modulus, a, b, output);
            }
            #[inline]
            fn reduce_sub_slice_rev_assign(self, a: &[#ty], b: &mut [#ty]) {
                #kernels::reduce_sub_slice_rev_assign(#modulus, a, b);
            }
        }
        // ReduceDoubleSlice
        impl ::primus_modulus::reduce::ReduceDoubleSlice<#ty> for #name {
            #[inline]
            fn reduce_double_slice_assign(self, values: &mut [#ty]) {
                #kernels::reduce_double_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_double_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                #kernels::reduce_double_slice_to(#modulus, input, output);
            }
        }
        // ReduceMulSlice
        impl ::primus_modulus::reduce::ReduceMulSlice<#ty> for #name {
            #[inline]
            fn reduce_mul_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                #kernels::reduce_mul_slice_assign #mul_generics(self, a, b);
            }
            #[inline]
            fn reduce_mul_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                #kernels::reduce_mul_slice_to #mul_generics(self, a, b, output);
            }
            #[inline]
            fn reduce_mul_scalar_slice_assign(self, a: &mut [#ty], scalar: #ty) {
                #kernels::reduce_mul_scalar_slice_assign #mul_generics(self, a, scalar);
            }
            #[inline]
            fn reduce_mul_scalar_slice_to(self, a: &[#ty], scalar: #ty, output: &mut [#ty]) {
                #kernels::reduce_mul_scalar_slice_to #mul_generics(self, a, scalar, output);
            }
        }
        // ReduceMulAddSlice
        impl ::primus_modulus::reduce::ReduceMulAddSlice<#ty> for #name {
            #[inline]
            fn reduce_add_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                // A declined native kernel leaves the destination untouched;
                // the ordinary constant-modulus implementation then fills it.
                if ::primus_modulus::BarrettModulus::<#ty>::from_parts(Self::value(), Self::ratio())
                    .__try_derived_add_mul_slice_assign(acc, a, b)
                {
                    return;
                }
                #kernels::reduce_add_mul_slice_assign #mul_generics(self, acc, a, b);
            }
            #[inline]
            fn reduce_sub_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                #kernels::reduce_sub_mul_slice_assign #mul_generics(self, acc, a, b);
            }
            #[inline]
            fn reduce_add_mul_scalar_slice_assign(self, acc: &mut [#ty], a: &[#ty], scalar: #ty) {
                #kernels::reduce_add_mul_scalar_slice_assign #mul_generics(self, acc, a, scalar);
            }
            #[inline]
            fn reduce_mul_add_slice_to(
                self,
                a: &[#ty],
                b: &[#ty],
                c: &[#ty],
                output: &mut [#ty],
            ) {
                // A declined native kernel leaves the destination untouched;
                // the ordinary constant-modulus implementation then fills it.
                if ::primus_modulus::BarrettModulus::<#ty>::from_parts(Self::value(), Self::ratio())
                    .__try_derived_mul_add_slice_to(a, b, c, output)
                {
                    return;
                }
                #kernels::reduce_mul_add_slice_to #mul_generics(self, a, b, c, output);
            }
            #[inline]
            fn reduce_mul_scalar_add_slice_to(
                self,
                a: &[#ty],
                scalar: #ty,
                c: &[#ty],
                output: &mut [#ty],
            ) {
                #kernels::reduce_mul_scalar_add_slice_to #mul_generics(self, a, scalar, c, output);
            }
        }

        impl ::primus_modulus::reduce::ReduceDotProductSigned<#ty> for #name {
            #[inline]
            fn reduce_dot_product_signed(
                self,
                lhs: &[#ty],
                rhs: &[<#ty as ::primus_modulus::integer::UnsignedInteger>::SignedInteger],
            ) -> #ty {
                #signed_dot_product(self, lhs, rhs)
            }
        }

        /// Accepts operands below `2^(BITS - 2)` for this unsigned coefficient
        /// type, even if they exceed the modulus. Both slice and iterator forms
        /// return canonical residues, using the same bound as runtime Barrett.
        impl ::primus_modulus::reduce::ReduceDotProduct<#ty> for #name {
            #[inline]
            fn reduce_dot_product(self, a: &[#ty], b: &[#ty]) -> #ty {
                #dot_product(self, a, b)
            }

            #[inline]
            fn reduce_dot_product_iter(
                self,
                a: impl IntoIterator<Item = #ty>,
                b: impl IntoIterator<Item = #ty>,
            ) -> #ty {
                ::primus_modulus::common::compact::slice::reduce_dot_product_iter(self, a, b)
            }
        }

    }
}

pub(crate) fn slice_inv_ops(name: &Ident, ty: &syn::Path) -> TokenStream {
    quote! {
        impl ::primus_modulus::reduce::ReduceInvSlice<#ty> for #name {
            #[inline]
            fn reduce_inv_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::reduce::{ReduceInv, ReduceMul, ReduceMulAssign};
                let len = input.len();

                debug_assert_eq!(output.len(), len);

                if len == 0 {
                    return;
                }

                let mut total_product = 1;
                for (prefix_product, &value) in output.iter_mut().zip(input.iter()) {
                    *prefix_product = total_product;
                    total_product = self.reduce_mul(total_product, value);
                }

                let mut suffix_inverse = self.reduce_inv(total_product);

                for (&value, prefix_product) in input.iter().rev().zip(output.iter_mut().rev()) {
                    self.reduce_mul_assign(prefix_product, suffix_inverse);
                    suffix_inverse = self.reduce_mul(suffix_inverse, value);
                }
            }
        }
        impl ::primus_modulus::reduce::TryReduceInvSlice<#ty> for #name {
            #[inline]
            fn try_reduce_inv_slice_to(
                self,
                input: &[#ty],
                output: &mut [#ty],
            ) -> Result<(), ::primus_modulus::reduce::ReduceError<#ty>> {
                use ::primus_modulus::reduce::{ReduceMul, ReduceMulAssign, TryReduceInv};
                let len = input.len();

                debug_assert_eq!(output.len(), len);

                if len == 0 {
                    return Ok(());
                }

                let mut total_product = 1;
                for (prefix_product, &value) in output.iter_mut().zip(input.iter()) {
                    *prefix_product = total_product;
                    total_product = self.reduce_mul(total_product, value);
                }

                let mut suffix_inverse = self.try_reduce_inv(total_product)?;

                for (&value, prefix_product) in input.iter().rev().zip(output.iter_mut().rev()) {
                    self.reduce_mul_assign(prefix_product, suffix_inverse);
                    suffix_inverse = self.reduce_mul(suffix_inverse, value);
                }

                Ok(())
            }
        }
    }
}
