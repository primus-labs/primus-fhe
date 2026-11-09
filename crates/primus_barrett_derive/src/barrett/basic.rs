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
            #[must_use]
            #vis const fn value() -> #ty {
                #modulus
            }

            /// Returns the little-endian limbs of `floor(B² / modulus)`, where `B = 2^BITS`.
            #[must_use]
            #[inline]
            #vis const fn ratio() -> [#ty; 2] {
                [#r0, #r1]
            }
        }

        impl ::primus_modulus::reduce::Modulus for #name {
            type ValueT = #ty;

            #[inline(always)]
            fn explicit_value(self) -> Option<Self::ValueT> {
                Some(#modulus)
            }

            #[inline(always)]
            fn minus_one(self) -> Self::ValueT {
                #modulus - 1
            }
        }

        impl ::primus_modulus::reduce::ExplicitModulus for #name {
            #[inline(always)]
            fn value(self) -> Self::ValueT {
                #modulus
            }
        }

        impl ::primus_modulus::reduce::PrepareModulusSwitch for #name {
            #[inline]
            fn prepare_switch_to<M: ::primus_modulus::reduce::Modulus<ValueT = #ty>>(self, target: M) -> ::primus_modulus::reduce::ModulusSwitch<#ty> {
                ::primus_modulus::reduce::ModulusSwitch::with_source_reciprocal(
                    #modulus,
                    target,
                    [#r0, #r1],
                )
            }
        }
        impl ::std::marker::Copy for #name {}

        impl ::std::clone::Clone for #name {
            #[inline]
            fn clone(&self) -> Self {
                *self
            }
        }

        impl ::std::cmp::PartialEq for #name {
            #[inline]
            fn eq(&self, _other: &Self) -> bool {
                true
            }
        }

        impl ::std::cmp::Eq for #name {}

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
                ::primus_modulus::SimdBarrettModulus::from_parts(#modulus, [#r0, #r1])
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
