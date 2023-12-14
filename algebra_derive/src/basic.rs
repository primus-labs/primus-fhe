use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::LitInt;

pub(crate) fn basic(name: &Ident, field_ty: &syn::Type, modulus: &LitInt) -> TokenStream {
    let name_str = name.to_string();
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

        impl Clone for #name {
            #[inline]
            fn clone(&self) -> Self {
                Self(self.0)
            }
        }

        impl Copy for #name {}

        impl std::fmt::Debug for #name {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(#name_str).field(&self.0).finish()
            }
        }

        impl Default for #name {
            #[inline]
            fn default() -> Self {
                Self(0)
            }
        }

        impl PartialOrd for #name {
            #[inline]
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }

        impl Ord for #name {
            #[inline]
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl PartialEq for #name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for #name {}
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
