use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

#[cfg(not(feature = "simd"))]
pub(crate) fn slice_ops(name: &Ident, modulus: &TokenStream, ty: &syn::Path) -> TokenStream {
    quote! {
        // ReduceOnceSlice
        impl ::primus_modulus::reduce::ReduceOnceSlice<#ty> for #name {
            #[inline]
            fn reduce_once_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_once_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_once_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_once_slice_to(#modulus, input, output);
            }
        }
        // ReduceNegSlice
        impl ::primus_modulus::reduce::ReduceNegSlice<#ty> for #name {
            #[inline]
            fn reduce_neg_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_neg_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_neg_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_neg_slice_to(#modulus, input, output);
            }
        }
        // ReduceAddSlice
        impl ::primus_modulus::reduce::ReduceAddSlice<#ty> for #name {
            #[inline]
            fn reduce_add_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_add_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn reduce_add_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_add_slice_to(#modulus, a, b, output);
            }
        }
        // ReduceSubSlice
        impl ::primus_modulus::reduce::ReduceSubSlice<#ty> for #name {
            #[inline]
            fn reduce_sub_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_sub_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn reduce_sub_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_sub_slice_to(#modulus, a, b, output);
            }
            #[inline]
            fn reduce_sub_slice_rev_assign(self, a: &[#ty], b: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_sub_slice_rev_assign(#modulus, a, b);
            }
        }
        // ReduceDoubleSlice
        impl ::primus_modulus::reduce::ReduceDoubleSlice<#ty> for #name {
            #[inline]
            fn reduce_double_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_double_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_double_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_double_slice_to(#modulus, input, output);
            }
        }
        // ReduceMulSlice
        impl ::primus_modulus::reduce::ReduceMulSlice<#ty> for #name {
            #[inline]
            fn reduce_mul_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_mul_slice_assign(self, a, b);
            }
            #[inline]
            fn reduce_mul_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_mul_slice_to(self, a, b, output);
            }
            #[inline]
            fn reduce_mul_scalar_slice_assign(self, a: &mut [#ty], scalar: #ty) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_mul_scalar_slice_assign(self, a, scalar);
            }
            #[inline]
            fn reduce_mul_scalar_slice_to(self, a: &[#ty], scalar: #ty, output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_mul_scalar_slice_to(self, a, scalar, output);
            }
        }
        // ReduceMulAddSlice
        impl ::primus_modulus::reduce::ReduceMulAddSlice<#ty> for #name {
            #[inline]
            fn reduce_add_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_add_mul_slice_assign(self, acc, a, b);
            }
            #[inline]
            fn reduce_sub_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_sub_mul_slice_assign(self, acc, a, b);
            }
            #[inline]
            fn reduce_add_mul_scalar_slice_assign(self, acc: &mut [#ty], a: &[#ty], scalar: #ty) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_add_mul_scalar_slice_assign(self, acc, a, scalar);
            }
            #[inline]
            fn reduce_mul_add_slice_to(
                self,
                a: &[#ty],
                b: &[#ty],
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_mul_add_slice_to(self, a, b, c, output);
            }
            #[inline]
            fn reduce_mul_scalar_add_slice_to(
                self,
                a: &[#ty],
                scalar: #ty,
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_mul_scalar_add_slice_to(self, a, scalar, c, output);
            }
        }

        // ReduceDotProduct
        impl ::primus_modulus::reduce::ReduceDotProduct<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn reduce_dot_product(self, a: impl AsRef<[#ty]>, b: impl AsRef<[#ty]>) -> Self::Output {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_dot_product(self, a.as_ref(), b.as_ref())
            }

            #[inline]
            fn reduce_dot_product_iter(
                self,
                a: impl IntoIterator<Item = #ty>,
                b: impl IntoIterator<Item = #ty>,
            ) -> Self::Output {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_dot_product_iter(self, a, b)
            }
        }

    }
}

#[cfg(feature = "simd")]
pub(crate) fn slice_ops(name: &Ident, modulus: &TokenStream, ty: &syn::Path) -> TokenStream {
    quote! {
        // ReduceOnceSlice
        impl ::primus_modulus::reduce::ReduceOnceSlice<#ty> for #name {
            #[inline]
            fn reduce_once_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_once_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_once_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_once_slice_to(#modulus, input, output);
            }
        }
        // ReduceNegSlice
        impl ::primus_modulus::reduce::ReduceNegSlice<#ty> for #name {
            #[inline]
            fn reduce_neg_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_neg_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_neg_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_neg_slice_to(#modulus, input, output);
            }
        }
        // ReduceAddSlice
        impl ::primus_modulus::reduce::ReduceAddSlice<#ty> for #name {
            #[inline]
            fn reduce_add_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_add_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn reduce_add_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_add_slice_to(#modulus, a, b, output);
            }
        }
        // ReduceSubSlice
        impl ::primus_modulus::reduce::ReduceSubSlice<#ty> for #name {
            #[inline]
            fn reduce_sub_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_sub_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn reduce_sub_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_sub_slice_to(#modulus, a, b, output);
            }
            #[inline]
            fn reduce_sub_slice_rev_assign(self, a: &[#ty], b: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_sub_slice_rev_assign(#modulus, a, b);
            }
        }
        // ReduceDoubleSlice
        impl ::primus_modulus::reduce::ReduceDoubleSlice<#ty> for #name {
            #[inline]
            fn reduce_double_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_double_slice_assign(#modulus, values);
            }
            #[inline]
            fn reduce_double_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::reduce_double_slice_to(#modulus, input, output);
            }
        }
        // ReduceMulSlice
        impl ::primus_modulus::reduce::ReduceMulSlice<#ty> for #name {
            #[inline]
            fn reduce_mul_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_mul_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, b,
                );
            }
            #[inline]
            fn reduce_mul_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_mul_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, b, output,
                );
            }
            #[inline]
            fn reduce_mul_scalar_slice_assign(self, a: &mut [#ty], scalar: #ty) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_mul_scalar_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, scalar,
                );
            }
            #[inline]
            fn reduce_mul_scalar_slice_to(self, a: &[#ty], scalar: #ty, output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_mul_scalar_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, scalar, output,
                );
            }
        }
        // ReduceMulAddSlice
        impl ::primus_modulus::reduce::ReduceMulAddSlice<#ty> for #name {
            #[inline]
            fn reduce_add_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_add_mul_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, acc, a, b,
                );
            }
            #[inline]
            fn reduce_sub_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_sub_mul_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, acc, a, b,
                );
            }
            #[inline]
            fn reduce_add_mul_scalar_slice_assign(
                self,
                acc: &mut [#ty],
                a: &[#ty],
                scalar: #ty,
            ) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_add_mul_scalar_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, acc, a, scalar,
                );
            }
            #[inline]
            fn reduce_mul_add_slice_to(
                self,
                a: &[#ty],
                b: &[#ty],
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_mul_add_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, b, c, output,
                );
            }
            #[inline]
            fn reduce_mul_scalar_add_slice_to(
                self,
                a: &[#ty],
                scalar: #ty,
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::reduce_mul_scalar_add_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, scalar, c, output,
                );
            }
        }

        // ReduceDotProduct
        impl ::primus_modulus::reduce::ReduceDotProduct<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn reduce_dot_product(self, a: impl AsRef<[#ty]>, b: impl AsRef<[#ty]>) -> Self::Output {
                ::primus_modulus::barrett_simd_reduce_dot_product(self, a.as_ref(), b.as_ref())
            }

            #[inline]
            fn reduce_dot_product_iter(
                self,
                a: impl IntoIterator<Item = #ty>,
                b: impl IntoIterator<Item = #ty>,
            ) -> Self::Output {
                use ::primus_modulus::common::compact::slice;
                slice::reduce_dot_product_iter(self, a, b)
            }
        }
    }
}

pub(crate) fn slice_inv_ops(name: &Ident, ty: &syn::Path) -> TokenStream {
    quote! {
        impl ::primus_modulus::reduce::ReduceInvSlice<#ty> for #name {
            #[inline]
            fn reduce_inv_slice_assign(self, values: &mut [#ty], prefix_products: &mut [#ty]) {
                use ::primus_modulus::reduce::{ReduceInv, ReduceMul};
                let len = values.len();

                debug_assert_eq!(prefix_products.len(), len);

                if len == 0 {
                    return;
                }

                let mut total_product = 1;
                for (prefix_product, &value) in prefix_products.iter_mut().zip(values.iter()) {
                    *prefix_product = total_product;
                    total_product = self.reduce_mul(total_product, value);
                }

                let mut suffix_inverse = self.reduce_inv(total_product);

                for (value, prefix_product) in values
                    .iter_mut()
                    .rev()
                    .zip(prefix_products.iter().rev().copied())
                {
                    let current_value = *value;
                    *value = self.reduce_mul(prefix_product, suffix_inverse);
                    suffix_inverse = self.reduce_mul(suffix_inverse, current_value);
                }
            }

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
            fn try_reduce_inv_slice_assign(
                self,
                values: &mut [#ty],
                prefix_products: &mut [#ty],
            ) -> Result<(), ::primus_modulus::reduce::ReduceError<#ty>> {
                use ::primus_modulus::reduce::{ReduceMul, TryReduceInv};
                let len = values.len();

                debug_assert_eq!(prefix_products.len(), len);

                if len == 0 {
                    return Ok(());
                }

                let mut total_product = 1;
                for (prefix_product, &value) in prefix_products.iter_mut().zip(values.iter()) {
                    *prefix_product = total_product;
                    total_product = self.reduce_mul(total_product, value);
                }

                let mut suffix_inverse = self.try_reduce_inv(total_product)?;

                for (value, prefix_product) in values
                    .iter_mut()
                    .rev()
                    .zip(prefix_products.iter().rev().copied())
                {
                    let current_value = *value;
                    *value = self.reduce_mul(prefix_product, suffix_inverse);
                    suffix_inverse = self.reduce_mul(suffix_inverse, current_value);
                }

                Ok(())
            }
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
