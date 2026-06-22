use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

pub(crate) fn basic(
    vis: &syn::Visibility,
    name: &Ident,
    modulus: &TokenStream,
    ty: &syn::Path,
    ratio: &[TokenStream; 2],
) -> TokenStream {
    let [r0, r1] = ratio;
    quote! {
        impl #name {
            /// Returns the modulus value.
            #vis const fn value() -> #ty {
                #modulus
            }

            /// Returns the ratio of this modulus.
            #[inline]
            #vis const fn ratio() -> [#ty; 2] {
                [#r0, #r1]
            }
        }

        impl ::primus_modulus::reduce::Modulus for #name {
            type ValueT = #ty;

            #[inline(always)]
            fn value(self) -> Option<Self::ValueT> {
                Some(#modulus)
            }

            #[inline(always)]
            unsafe fn value_unchecked(self) -> Self::ValueT {
                #modulus
            }

            #[inline(always)]
            fn minus_one(self) -> Self::ValueT {
                #modulus - 1
            }
        }

        impl ::std::marker::Copy for #name {}

        impl ::std::clone::Clone for #name {
            #[inline]
            fn clone(&self) -> Self {
                *self
            }
        }

        impl ::std::fmt::Debug for #name {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", #modulus)
            }
        }

        impl ::std::hash::Hash for #name {
            #[inline]
            fn hash<H: ::std::hash::Hasher>(&self, state: &mut H){
                #modulus.hash(state)
            }
        }
    }
}

#[cfg(feature = "simd")]
pub(crate) fn into_simd_modulus(
    name: &Ident,
    modulus: &TokenStream,
    ty: &syn::Path,
    ratio: &[TokenStream; 2],
) -> TokenStream {
    let [r0, r1] = ratio;
    quote! {
        impl ::std::convert::Into<::primus_modulus::SimdBarrettModulus<#ty>> for #name {
            #[inline]
            fn into(self) -> ::primus_modulus::SimdBarrettModulus<#ty> {
                ::primus_modulus::SimdBarrettModulus::new(#modulus, [#r0, #r1])
            }
        }
    }
}

#[cfg(not(feature = "simd"))]
pub(crate) fn into_simd_modulus(
    _name: &Ident,
    _modulus: &TokenStream,
    _ty: &syn::Path,
    _ratio: &[TokenStream; 2],
) -> TokenStream {
    TokenStream::new()
}
