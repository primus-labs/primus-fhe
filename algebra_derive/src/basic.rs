use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::LitInt;

pub(crate) fn basic(name: &Ident, field_ty: &syn::Type, modulus: &LitInt) -> TokenStream {
    quote! {
        impl #name {
            /// Return max value
            #[inline]
            pub const fn max() -> Self {
                Self(#modulus - 1)
            }
        }

        impl From<#field_ty> for #name {
            #[inline]
            fn from(value: #field_ty) -> Self {
                Self(value)
            }
        }
    }
}

pub(crate) fn display(name: &Ident, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::std::fmt::Display for #name {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "[({})_{}]", self.0, #modulus)
            }
        }
    }
}

pub(crate) fn impl_zero(name: &Ident) -> TokenStream {
    quote! {
        impl num_traits::Zero for #name {
            #[inline]
            fn zero() -> Self {
                Self(0)
            }

            #[inline]
            fn is_zero(&self) -> bool {
                self.0 == 0
            }

            #[inline]
            fn set_zero(&mut self) {
                self.0 = 0;
            }
        }
    }
}

pub(crate) fn impl_one(name: &Ident) -> TokenStream {
    quote! {
        impl num_traits::One for #name {
            #[inline]
            fn one() -> Self {
                Self(1)
            }

            #[inline]
            fn set_one(&mut self) {
                self.0 = 1;
            }

            #[inline]
            fn is_one(&self) -> bool
            {
                self.0 == 1
            }
        }
    }
}
