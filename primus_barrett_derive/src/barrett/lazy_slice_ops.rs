use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

pub(crate) fn impl_lazy_reduce_slice_ops(
    name: &Ident,
    modulus: &TokenStream,
    ty: &syn::Path,
) -> TokenStream {
    quote! {
        // -----------------------------------------------------------------
        // LazyReduceNegSlice
        // -----------------------------------------------------------------
        #[cfg(not(feature = "simd"))]
        impl ::primus_modulus::reduce::LazyReduceNegSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_neg_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_neg_slice_assign(#modulus, values);
            }
            #[inline]
            fn lazy_reduce_neg_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_neg_slice_to(#modulus, input, output);
            }
        }
        #[cfg(feature = "simd")]
        impl ::primus_modulus::reduce::LazyReduceNegSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_neg_slice_assign(self, values: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::lazy_reduce_neg_slice_assign(#modulus, values);
            }
            #[inline]
            fn lazy_reduce_neg_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::lazy_reduce_neg_slice_to(#modulus, input, output);
            }
        }
        // -----------------------------------------------------------------
        // LazyReduceSubSlice
        // -----------------------------------------------------------------
        #[cfg(not(feature = "simd"))]
        impl ::primus_modulus::reduce::LazyReduceSubSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_sub_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_sub_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn lazy_reduce_sub_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_sub_slice_to(#modulus, a, b, output);
            }
            #[inline]
            fn lazy_reduce_sub_slice_rev_assign(self, a: &[#ty], b: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_sub_slice_rev_assign(#modulus, a, b);
            }
        }
        #[cfg(feature = "simd")]
        impl ::primus_modulus::reduce::LazyReduceSubSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_sub_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::lazy_reduce_sub_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn lazy_reduce_sub_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::lazy_reduce_sub_slice_to(#modulus, a, b, output);
            }
            #[inline]
            fn lazy_reduce_sub_slice_rev_assign(self, a: &[#ty], b: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                simd::lazy_reduce_sub_slice_rev_assign(#modulus, a, b);
            }
        }
        // -----------------------------------------------------------------
        // LazyReduceMulSlice
        // -----------------------------------------------------------------
        #[cfg(not(feature = "simd"))]
        impl ::primus_modulus::reduce::LazyReduceMulSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_mul_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_mul_slice_assign(self, a, b);
            }
            #[inline]
            fn lazy_reduce_mul_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_mul_slice_to(self, a, b, output);
            }
            #[inline]
            fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [#ty], scalar: #ty) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_mul_scalar_slice_assign(self, a, scalar);
            }
            #[inline]
            fn lazy_reduce_mul_scalar_slice_to(self, a: &[#ty], scalar: #ty, output: &mut [#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_mul_scalar_slice_to(self, a, scalar, output);
            }
        }

        #[cfg(feature = "simd")]
        impl ::primus_modulus::reduce::LazyReduceMulSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_mul_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_mul_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, b,
                );
            }
            #[inline]
            fn lazy_reduce_mul_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_mul_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, b, output,
                );
            }
            #[inline]
            fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [#ty], scalar: #ty) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_mul_scalar_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, scalar,
                );
            }
            #[inline]
            fn lazy_reduce_mul_scalar_slice_to(
                self, a: &[#ty], scalar: #ty, output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_mul_scalar_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, scalar, output,
                );
            }
        }

        // -----------------------------------------------------------------
        // LazyReduceMulAddSlice
        // -----------------------------------------------------------------

        #[cfg(not(feature = "simd"))]
        impl ::primus_modulus::reduce::LazyReduceMulAddSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_add_mul_slice_assign(self, acc, a, b);
            }

            #[inline]
            fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_sub_mul_slice_assign(self, acc, a, b);
            }

            #[inline]
            fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [#ty], a: &[#ty], scalar: #ty) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_add_mul_scalar_slice_assign(self, acc, a, scalar);
            }

            #[inline]
            fn lazy_reduce_mul_add_slice_to(
                self,
                a: &[#ty],
                b: &[#ty],
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_mul_add_slice_to(self, a, b, c, output);
            }

            #[inline]
            fn lazy_reduce_mul_scalar_add_slice_to(
                self,
                a: &[#ty],
                scalar: #ty,
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::slice;
                slice::lazy_reduce_mul_scalar_add_slice_to(self, a, scalar, c, output);
            }
        }

        #[cfg(feature = "simd")]
        impl ::primus_modulus::reduce::LazyReduceMulAddSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_add_mul_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, acc, a, b,
                );
            }

            #[inline]
            fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_sub_mul_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, acc, a, b,
                );
            }

            #[inline]
            fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [#ty], a: &[#ty], scalar: #ty) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_add_mul_scalar_slice_assign::<#ty, Self, SimdBarrettModulus<#ty>>(self, acc, a, scalar);
            }

            #[inline]
            fn lazy_reduce_mul_add_slice_to(
                self,
                a: &[#ty],
                b: &[#ty],
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_mul_add_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, b, c, output,
                );
            }

            #[inline]
            fn lazy_reduce_mul_scalar_add_slice_to(
                self,
                a: &[#ty],
                scalar: #ty,
                c: &[#ty],
                output: &mut [#ty],
            ) {
                use ::primus_modulus::common::compact::simd;
                use ::primus_modulus::SimdBarrettModulus;
                simd::lazy_reduce_mul_scalar_add_slice_to::<#ty, Self, SimdBarrettModulus<#ty>>(
                    self, a, scalar, c, output,
                );
            }
        }
    }
}
