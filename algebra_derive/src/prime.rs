use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::ast::Input;

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_prime(input))
}

fn impl_prime(input: Input) -> TokenStream {
    let name = &input.ident;
    // let field_ty = input.field.ty;

    quote! {
        impl algebra::field::PrimeField for #name {
            #[doc = concat!("Check [`", stringify!(#name), "`] is a prime field.")]
            #[inline]
            fn is_prime_field() -> bool {
                algebra::utils::Prime::probably_prime(&<Self as algebra::field::BarrettConfig>::BARRETT_MODULUS, 20)
            }
        }
    }
}
