use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::ast::Input;

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    Ok(impl_ring(Input::from_syn(input)?))
}

fn impl_ring(input: Input) -> TokenStream {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let inner_ty = input.field.ty;

    let modulus = input.attrs.modulus.unwrap();

    let impl_display = quote! {
        impl #impl_generics core::fmt::Display for #name #ty_generics #where_clause {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "[({})_{}]", self.0, #modulus)
            }
        }
    };

    let impl_barrett = quote! {
        impl #impl_generics BarrettConfig<#inner_ty> for #name #ty_generics #where_clause {
            const BARRETT_MODULUS: Modulus<#inner_ty> = Modulus::<#inner_ty>::new(#modulus);
        }
    };

    let impl_add = quote! {
        impl #impl_generics core::ops::Add<Self> for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn add(self, rhs: Self) -> Self::Output {
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl #impl_generics core::ops::Add<&Self> for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn add(self, rhs: &Self) -> Self::Output {
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl #impl_generics core::ops::AddAssign<Self> for #name #ty_generics #where_clause {
            #[inline]
            fn add_assign(&mut self, rhs: Self) {
                self.0.add_reduce_assign(rhs.0, #modulus)
            }
        }

        impl #impl_generics core::ops::AddAssign<&Self> for #name #ty_generics #where_clause {
            #[inline]
            fn add_assign(&mut self, rhs: &Self) {
                self.0.add_reduce_assign(rhs.0, #modulus)
            }
        }
    };

    let impl_sub = quote! {
        impl #impl_generics core::ops::Sub<Self> for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: Self) -> Self::Output {
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl #impl_generics core::ops::Sub<&Self> for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: &Self) -> Self::Output {
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl #impl_generics core::ops::SubAssign<Self> for #name #ty_generics #where_clause {
            #[inline]
            fn sub_assign(&mut self, rhs: Self) {
                self.0.sub_reduce_assign(rhs.0, #modulus)
            }
        }

        impl #impl_generics core::ops::SubAssign<&Self> for #name #ty_generics #where_clause {
            #[inline]
            fn sub_assign(&mut self, rhs: &Self) {
                self.0.sub_reduce_assign(rhs.0, #modulus)
            }
        }
    };

    let impl_mul = quote! {
        impl #impl_generics core::ops::Mul<Self> for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: Self) -> Self::Output {
                Self(self.0.mul_reduce(rhs.0, &Self::BARRETT_MODULUS))
            }
        }

        impl #impl_generics core::ops::Mul<&Self> for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: &Self) -> Self::Output {
                Self(self.0.mul_reduce(rhs.0, &Self::BARRETT_MODULUS))
            }
        }

        impl #impl_generics core::ops::MulAssign<Self> for #name #ty_generics #where_clause {
            #[inline]
            fn mul_assign(&mut self, rhs: Self) {
                self.0.mul_reduce_assign(rhs.0, &Self::BARRETT_MODULUS)
            }
        }

        impl #impl_generics core::ops::MulAssign<&Self> for #name #ty_generics #where_clause {
            #[inline]
            fn mul_assign(&mut self, rhs: &Self) {
                self.0.mul_reduce_assign(rhs.0, &Self::BARRETT_MODULUS)
            }
        }
    };

    let impl_neg = quote! {
        impl #impl_generics core::ops::Neg for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self::Output {
                Self(self.0.neg_reduce(#modulus))
            }
        }
    };

    let impl_pow = quote! {
        impl #impl_generics num_traits::Pow<<Self as Ring>::Order> for #name #ty_generics #where_clause {
            type Output = Self;

            #[inline]
            fn pow(self, rhs: <Self as Ring>::Order) -> Self::Output {
                Self(self.0.pow_reduce(rhs, &Self::BARRETT_MODULUS))
            }
        }
    };

    let impl_ring = quote! {
        impl #impl_generics Ring for #name #ty_generics #where_clause {
            type Scalar = #inner_ty;

            type Order = #inner_ty;

            type Base = #inner_ty;

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn mul_scalar(&self, scalar: Self::Scalar) -> Self {
                Self(self.0.mul_reduce(scalar, &Self::BARRETT_MODULUS))
            }
        }
    };

    quote! {
        #impl_display

        #impl_barrett

        #impl_add

        #impl_sub

        #impl_mul

        #impl_neg

        #impl_pow

        #impl_ring
    }
}
