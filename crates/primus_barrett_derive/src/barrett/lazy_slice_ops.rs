use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

pub(crate) fn lazy_slice_ops(name: &Ident, modulus: &TokenStream, ty: &syn::Path) -> TokenStream {
    let kernels = super::slice_kernels::kernel_module();
    let mul_generics = super::slice_kernels::multiplication_generics(ty);

    quote! {
        // LazyReduceNegSlice
        impl ::primus_modulus::reduce::LazyReduceNegSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_neg_slice_assign(self, values: &mut [#ty]) {
                #kernels::lazy_reduce_neg_slice_assign(#modulus, values);
            }
            #[inline]
            fn lazy_reduce_neg_slice_to(self, input: &[#ty], output: &mut [#ty]) {
                #kernels::lazy_reduce_neg_slice_to(#modulus, input, output);
            }
        }
        // LazyReduceSubSlice
        impl ::primus_modulus::reduce::LazyReduceSubSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_sub_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                #kernels::lazy_reduce_sub_slice_assign(#modulus, a, b);
            }
            #[inline]
            fn lazy_reduce_sub_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                #kernels::lazy_reduce_sub_slice_to(#modulus, a, b, output);
            }
            #[inline]
            fn lazy_reduce_sub_slice_rev_assign(self, a: &[#ty], b: &mut [#ty]) {
                #kernels::lazy_reduce_sub_slice_rev_assign(#modulus, a, b);
            }
        }
        // LazyReduceMulSlice
        impl ::primus_modulus::reduce::LazyReduceMulSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_mul_slice_assign(self, a: &mut [#ty], b: &[#ty]) {
                #kernels::lazy_reduce_mul_slice_assign #mul_generics(self, a, b);
            }
            #[inline]
            fn lazy_reduce_mul_slice_to(self, a: &[#ty], b: &[#ty], output: &mut [#ty]) {
                #kernels::lazy_reduce_mul_slice_to #mul_generics(self, a, b, output);
            }
            #[inline]
            fn lazy_reduce_mul_scalar_slice_assign(self, a: &mut [#ty], scalar: #ty) {
                #kernels::lazy_reduce_mul_scalar_slice_assign #mul_generics(self, a, scalar);
            }
            #[inline]
            fn lazy_reduce_mul_scalar_slice_to(self, a: &[#ty], scalar: #ty, output: &mut [#ty]) {
                #kernels::lazy_reduce_mul_scalar_slice_to #mul_generics(self, a, scalar, output);
            }
        }
        // LazyReduceMulAddSlice
        impl ::primus_modulus::reduce::LazyReduceMulAddSlice<#ty> for #name {
            #[inline]
            fn lazy_reduce_add_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                #kernels::lazy_reduce_add_mul_slice_assign #mul_generics(self, acc, a, b);
            }

            #[inline]
            fn lazy_reduce_sub_mul_slice_assign(self, acc: &mut [#ty], a: &[#ty], b: &[#ty]) {
                #kernels::lazy_reduce_sub_mul_slice_assign #mul_generics(self, acc, a, b);
            }

            #[inline]
            fn lazy_reduce_add_mul_scalar_slice_assign(self, acc: &mut [#ty], a: &[#ty], scalar: #ty) {
                #kernels::lazy_reduce_add_mul_scalar_slice_assign #mul_generics(self, acc, a, scalar);
            }

            #[inline]
            fn lazy_reduce_mul_add_slice_to(
                self,
                a: &[#ty],
                b: &[#ty],
                c: &[#ty],
                output: &mut [#ty],
            ) {
                #kernels::lazy_reduce_mul_add_slice_to #mul_generics(self, a, b, c, output);
            }

            #[inline]
            fn lazy_reduce_mul_scalar_add_slice_to(
                self,
                a: &[#ty],
                scalar: #ty,
                c: &[#ty],
                output: &mut [#ty],
            ) {
                #kernels::lazy_reduce_mul_scalar_add_slice_to #mul_generics(self, a, scalar, c, output);
            }
        }
    }
}
