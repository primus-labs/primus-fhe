use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::Type;

pub(crate) fn basic(name: &Ident, modulus: &TokenStream) -> TokenStream {
    let name_str = name.to_string();
    quote! {
        impl #name {
            /// Return max value
            #[inline]
            pub const fn max() -> Self {
                Self(#modulus - 1)
            }

            /// Return -1
            #[inline]
            pub const fn neg_one() -> Self {
                Self(#modulus - 1)
            }
        }

        impl ::std::clone::Clone for #name {
            #[inline]
            fn clone(&self) -> Self {
                *self
            }
        }

        impl ::std::marker::Copy for #name {}

        impl ::std::fmt::Debug for #name {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_tuple(#name_str).field(&self.0).finish()
            }
        }

        impl ::std::default::Default for #name {
            #[inline]
            fn default() -> Self {
                Self(0)
            }
        }

        impl ::std::cmp::PartialOrd for #name {
            #[inline]
            fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::std::cmp::Ord for #name {
            #[inline]
            fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl ::std::cmp::PartialEq for #name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl ::std::cmp::Eq for #name {}

        impl ::std::hash::Hash for #name {
            #[inline]
            fn hash<H: ::std::hash::Hasher>(&self, state: &mut H){
                self.0.hash(state)
            }
        }
    }
}

pub(crate) fn display(name: &Ident) -> TokenStream {
    quote! {
        impl ::std::fmt::Display for #name {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    }
}

pub(crate) fn impl_zero(name: &Ident) -> TokenStream {
    quote! {
        impl ::num_traits::Zero for #name {
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

        impl ::num_traits::ConstZero for #name {
            const ZERO: Self = Self(0);
        }
    }
}

pub(crate) fn impl_one(name: &Ident) -> TokenStream {
    quote! {
        impl ::num_traits::One for #name {
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

        impl ::num_traits::ConstOne for #name {
            const ONE: Self = Self(1);
        }
    }
}

pub(crate) fn impl_neg_one(name: &Ident, modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::algebra::NegOne for #name {
            #[inline]
            fn neg_one() -> Self {
                Self(#modulus - 1)
            }

            #[inline]
            fn set_neg_one(&mut self) {
                self.0 = #modulus - 1;
            }

            #[inline]
            fn is_neg_one(&self) -> bool
            {
                self.0 == #modulus - 1
            }
        }

        impl ::algebra::ConstNegOne for #name {
            const NEG_ONE: Self = Self(#modulus - 1);
        }
    }
}

pub(crate) fn impl_ser(name: &Ident, field_ty: &Type) -> TokenStream {
    let serializer_fn = match field_ty {
        Type::Path(type_path) if type_path.path.is_ident("u8") => quote! { serialize_u8 },
        Type::Path(type_path) if type_path.path.is_ident("u16") => quote! { serialize_u16 },
        Type::Path(type_path) if type_path.path.is_ident("u32") => quote! { serialize_u32 },
        Type::Path(type_path) if type_path.path.is_ident("u64") => quote! { serialize_u64 },
        _ => panic!("Unsupported type"),
    };

    quote! {
        impl ::serde::Serialize for #name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: ::serde::Serializer,
            {
                serializer.#serializer_fn(self.0)
            }
        }
    }
}

pub(crate) fn impl_deser(name: &Ident, field_ty: &Type) -> TokenStream {
    let deser_type = match field_ty {
        Type::Path(type_path) if type_path.path.is_ident("u8") => quote! { u8 },
        Type::Path(type_path) if type_path.path.is_ident("u16") => quote! { u16 },
        Type::Path(type_path) if type_path.path.is_ident("u32") => quote! { u32 },
        Type::Path(type_path) if type_path.path.is_ident("u64") => quote! { u64 },
        _ => panic!("Unsupported type"),
    };

    quote! {
        impl<'de> ::serde::Deserialize<'de> for #name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: ::serde::Deserializer<'de>,
            {
                let value = #deser_type::deserialize(deserializer)?;
                Ok(::algebra::Field::new(value))
            }
        }
    }
}
