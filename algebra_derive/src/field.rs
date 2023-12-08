use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::{ast::Input, ops::*};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_field_with_ops(input))
}

fn impl_field_with_ops(input: Input) -> TokenStream {
    let name = &input.ident;

    // let _field_ty = input.field.ty;

    let modulus = input.attrs.modulus.unwrap();

    let impl_div = div_reduce_ops(name);

    let impl_inv = inv_reduce_ops(name, &modulus);

    let impl_field = impl_field(name);

    quote! {
        #impl_div

        #impl_inv

        #impl_field
    }
}

fn impl_field(name: &proc_macro2::Ident) -> TokenStream {
    quote! {
        impl algebra::field::Field for #name {}
    }
}
