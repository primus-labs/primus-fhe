use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::ast::Input;

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_fhe_field(input))
}

fn impl_fhe_field(input: Input) -> TokenStream {
    let name = &input.ident;

    quote! {
        impl ::algebra::FheField for #name{
            #[inline]
            fn lazy_new(value: Self::Value) -> Self {
                Self(value)
            }

            #[inline]
            fn add_mul(self, a: Self, b: Self) -> Self {
                use ::algebra::reduce::Reduce;
                Self(::algebra::CarryingMul::carrying_mul(a.0, b.0, self.0).reduce(<Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn mul_fast(self, rhs: Self) -> Self {
                use ::algebra::reduce::LazyMulReduce;
                Self(self.0.lazy_mul_reduce(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn add_mul_fast(self, a: Self, b: Self) -> Self {
                use ::algebra::Widening;
                use ::algebra::reduce::LazyReduce;
                Self(::algebra::CarryingMul::carrying_mul(a.0, b.0, self.0).lazy_reduce(<Self as ::algebra::ModulusConfig>::MODULUS))
            }
        }
    }
}
