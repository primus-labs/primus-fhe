use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result, Type};

use crate::{
    ast::Input,
    basic::{basic, display, impl_deser, impl_neg_one, impl_one, impl_ser, impl_zero},
    ops::*,
};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    impl_field_with_ops(input)
}

fn impl_field_with_ops(input: Input) -> Result<TokenStream> {
    let name = &input.ident;

    let modulus_value = input.attrs.modulus_value;
    modulus_value.check_leading_zeros(input.field.original)?;
    let modulus = modulus_value.into_token_stream();

    let field_ty = input.field.ty;

    let impl_ser = impl_ser(name, field_ty);

    let impl_deser = impl_deser(name, field_ty);

    let impl_basic = basic(name, &modulus);

    let impl_display = display(name);

    let impl_zero = impl_zero(name);

    let impl_one = impl_one(name);

    let impl_neg_one = impl_neg_one(name, &modulus);

    let impl_modulus_config =
        impl_modulus_config(name, field_ty, input.attrs.modulus_type, &modulus);

    let impl_add = add_reduce_ops(name, &modulus);

    let impl_sub = sub_reduce_ops(name, &modulus);

    let impl_mul = mul_reduce_ops(name);

    let impl_neg = neg_reduce_ops(name, &modulus);

    let impl_pow = pow_reduce_ops(name);

    let impl_div = div_reduce_ops(name);

    let impl_inv = inv_reduce_ops(name, &modulus);

    let impl_field = impl_field(name, field_ty, &modulus);

    Ok(quote! {
        #impl_ser

        #impl_deser

        #impl_basic

        #impl_zero

        #impl_one

        #impl_neg_one

        #impl_display

        #impl_modulus_config

        #impl_add

        #impl_sub

        #impl_mul

        #impl_neg

        #impl_pow

        #impl_div

        #impl_inv

        #impl_field
    })
}

#[inline]
fn impl_field(name: &proc_macro2::Ident, field_ty: &Type, modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::algebra::Field for #name {
            type Value = #field_ty;

            type Order = #field_ty;

            const MODULUS_VALUE: Self::Value = #modulus;

            #[inline]
            fn new(value: Self::Value) -> Self {
                if value < #modulus {
                    Self(value)
                } else {
                    use ::algebra::reduce::Reduce;
                    Self(value.reduce(<Self as ::algebra::ModulusConfig>::MODULUS))
                }
            }

            #[inline]
            fn value(self) -> Self::Value {
                self.0
            }
        }
    }
}
