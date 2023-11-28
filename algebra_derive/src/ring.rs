use proc_macro2::{Ident, TokenStream};
use quote::{quote, ToTokens};
use syn::{DeriveInput, LitInt, Result, Type};

use crate::{ast::Input, basic::*, ops::*};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    Ok(impl_ring_with_ops(Input::from_syn(input)?))
}

enum FieldType {
    U8,
    U16,
    U32,
    U64,
    Unsupported,
}

fn impl_ring_with_ops(input: Input) -> TokenStream {
    let name = &input.ident;

    let field_ty = input.field.ty;

    let modulus = input.attrs.modulus.unwrap();

    let modulus_number: u128 = modulus
        .base10_digits()
        .parse()
        .expect("Modulus should be a number");

    let tralling_zeros = modulus_number.trailing_zeros();

    let pow_of_two = modulus_number.is_power_of_two();
    let field_type: FieldType;
    match field_ty {
        Type::Path(type_path) => {
            if type_path.clone().into_token_stream().to_string() == "u8" {
                field_type = FieldType::U8;
                let mask = 1u8 << tralling_zeros - 1;
            } else if type_path.clone().into_token_stream().to_string() == "u16" {
                field_type = FieldType::U16;
            } else if type_path.clone().into_token_stream().to_string() == "u32" {
                field_type = FieldType::U32;
            } else if type_path.clone().into_token_stream().to_string() == "u64" {
                field_type = FieldType::U64
            } else {
                field_type = FieldType::Unsupported
            }
        }
        _ => field_type = FieldType::Unsupported,
    }

    let impl_basic = basic(name, field_ty, &modulus);

    let impl_display = display(name, &modulus);

    let impl_zero = impl_zero(name);

    let impl_one = impl_one(name);

    let impl_barrett = barrett(name, field_ty, &modulus);

    let impl_add = add_reduce_ops(name, &modulus);

    let impl_sub = sub_reduce_ops(name, &modulus);

    let impl_mul = mul_reduce_ops(name, field_ty);

    let impl_neg = neg_reduce_ops(name, &modulus);

    let impl_pow = pow_reduce_ops(name, field_ty);

    let impl_ring = impl_ring(name, field_ty, &modulus);

    quote! {
        #impl_basic

        #impl_zero

        #impl_one

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

fn impl_ring(name: &Ident, field_ty: &Type, modulus: &LitInt) -> TokenStream {
    quote! {
        impl algebra::ring::Ring for #name {
            type Scalar = #field_ty;

            type Order = #field_ty;

            type Base = #field_ty;

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn mul_scalar(&self, scalar: Self::Scalar) -> Self {
                use algebra::modulo_traits::MulModulo;
                Self(self.0.mul_reduce(scalar, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS))
            }
        }
    }
}
