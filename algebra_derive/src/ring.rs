use proc_macro2::{Ident, TokenStream};
use quote::{quote, ToTokens};
use syn::{DeriveInput, Error, LitInt, Result, Type};

use crate::{ast::Input, basic::*, ops::*};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    impl_ring_with_ops(Input::from_syn(input)?)
}

fn impl_ring_with_ops(input: Input) -> Result<TokenStream> {
    let name = &input.ident;
    let field_ty = input.field.ty;
    let modulus = input.attrs.modulus.unwrap();

    let pow_of_two: bool;
    let mask = match field_ty {
        Type::Path(type_path) => {
            if type_path.clone().into_token_stream().to_string() == "u8" {
                let modulus_number: u8 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u8 type.",
                    )
                })?;
                pow_of_two = modulus_number.is_power_of_two();
                let mask = modulus_number - 1;
                mask.into_token_stream()
            } else if type_path.clone().into_token_stream().to_string() == "u16" {
                let modulus_number: u16 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u16 type.",
                    )
                })?;
                pow_of_two = modulus_number.is_power_of_two();
                let mask = modulus_number - 1;
                mask.into_token_stream()
            } else if type_path.clone().into_token_stream().to_string() == "u32" {
                let modulus_number: u32 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u32 type.",
                    )
                })?;
                pow_of_two = modulus_number.is_power_of_two();
                let mask = modulus_number - 1;
                mask.into_token_stream()
            } else if type_path.clone().into_token_stream().to_string() == "u64" {
                let modulus_number: u64 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u64 type.",
                    )
                })?;
                pow_of_two = modulus_number.is_power_of_two();
                let mask = modulus_number - 1;
                mask.into_token_stream()
            } else {
                return Err(Error::new_spanned(
                    input.field.original,
                    "The type supplied is unsupported.",
                ));
            }
        }
        _ => {
            return Err(Error::new_spanned(
                input.original,
                "Unable to check the inner type.",
            ))
        }
    };

    let impl_basic = basic(name, field_ty, &modulus);

    let impl_display = display(name, &modulus);

    let impl_zero = impl_zero(name);

    let impl_one = impl_one(name);

    if pow_of_two {
        let impl_add = add_and_ops(name, &mask);

        let impl_sub = sub_and_ops(name, &mask);

        let impl_mul = mul_and_ops(name, &mask);

        let impl_neg = neg_and_ops(name, &modulus);

        let impl_pow = pow_and_ops(name, field_ty, &modulus, &mask);

        let impl_ring = impl_and_ring(name, field_ty, &modulus, &mask);

        Ok(quote! {
            #impl_basic

            #impl_zero

            #impl_one

            #impl_display

            #impl_add

            #impl_sub

            #impl_mul

            #impl_neg

            #impl_pow

            #impl_ring
        })
    } else {
        let impl_barrett = barrett(name, field_ty, &modulus);

        let impl_add = add_reduce_ops(name, &modulus);

        let impl_sub = sub_reduce_ops(name, &modulus);

        let impl_mul = mul_reduce_ops(name);

        let impl_neg = neg_reduce_ops(name, &modulus);

        let impl_pow = pow_reduce_ops(name);

        let impl_ring = impl_ring(name, field_ty, &modulus);

        Ok(quote! {
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
        })
    }
}

fn impl_ring(name: &Ident, field_ty: &Type, modulus: &LitInt) -> TokenStream {
    quote! {
        impl algebra::ring::Ring for #name {
            type Inner =#field_ty;

            type Scalar = #field_ty;

            type Order = #field_ty;

            type Base = #field_ty;

            type Modulus = #field_ty;

            #[inline]
            fn modulus() -> Self::Modulus {
                #modulus
            }

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn mul_scalar(&self, scalar: Self::Scalar) -> Self {
                use algebra::modulo_traits::MulModulo;
                Self(self.0.mul_reduce(scalar, &<Self as algebra::field::BarrettConfig>::BARRETT_MODULUS))
            }
        }
    }
}

fn impl_and_ring(
    name: &Ident,
    field_ty: &Type,
    modulus: &LitInt,
    mask: &TokenStream,
) -> TokenStream {
    quote! {
        impl algebra::ring::Ring for #name {
            type Inner =#field_ty;

            type Scalar = #field_ty;

            type Order = #field_ty;

            type Base = #field_ty;

            type Modulus = #field_ty;

            #[inline]
            fn modulus() -> Self::Modulus {
                #modulus
            }

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn mul_scalar(&self, scalar: Self::Scalar) -> Self {
                Self(self.0.wrapping_mul(scalar) & #mask)
            }
        }
    }
}
