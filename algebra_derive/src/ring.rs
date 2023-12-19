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
            type Inner = #field_ty;

            type Scalar = #field_ty;

            type Order = #field_ty;

            #[doc = concat!("Creates a new [`", stringify!(#name), "`].")]
            #[inline]
            fn new(value: #field_ty) -> Self {
                Self(value)
            }

            /// Return inner value
            #[inline]
            fn inner(self) -> #field_ty {
                self.0
            }

            /// cast inner to [`usize`]
            #[inline]
            fn cast_into_usize(value: Self::Inner) -> usize {
                value as usize
            }

            /// cast inner from [`usize`]
            #[inline]
            fn cast_from_usize(value: usize) -> Self {
                Self::new(value as #field_ty)
            }

            #[inline]
            fn modulus() -> Self::Inner {
                #modulus
            }

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn decompose_len(basis: usize) -> usize {
                debug_assert!(basis.is_power_of_two());
                algebra::div_ceil(<Self as algebra::field::BarrettConfig>::barrett_modulus().bit_count(), basis.trailing_zeros()) as usize
            }

            fn decompose(&self, basis: usize) -> Vec<Self> {
                let mut temp = self.0;
                let bits = basis.trailing_zeros();

                let len = Self::decompose_len(basis);
                let mask = #field_ty::MAX >> (#field_ty::BITS - bits);
                let mut ret: Vec<Self> = Vec::with_capacity(len);

                while temp != 0 {
                    ret.push(Self(temp & mask));
                    temp >>= bits;
                }

                ret.resize(len, #name(0));

                ret
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
            type Inner = #field_ty;

            type Scalar = #field_ty;

            type Order = #field_ty;

            #[doc = concat!("Creates a new [`", stringify!(#name), "`].")]
            #[inline]
            fn new(value: #field_ty) -> Self {
                Self(value)
            }

            /// Return inner value
            #[inline]
            fn inner(self) -> #field_ty {
                self.0
            }

            /// cast inner to [`usize`]
            #[inline]
            fn cast_into_usize(value: Self::Inner) -> usize {
                value as usize
            }

            /// cast inner from [`usize`]
            #[inline]
            fn cast_from_usize(value: usize) -> Self {
                Self::new(value as #field_ty)
            }

            #[inline]
            fn modulus() -> Self::Inner {
                #modulus
            }

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn decompose_len(basis: usize) -> usize {
                debug_assert!(basis.is_power_of_two());
                algebra::div_ceil(Self::modulus().trailing_zeros(), basis.trailing_zeros()) as usize
            }

            fn decompose(&self, basis: usize) -> Vec<Self> {
                let mut temp = self.0;
                let bits = basis.trailing_zeros();

                let len = Self::decompose_len(basis);
                let mask = #field_ty::MAX >> (#field_ty::BITS - bits);
                let mut ret: Vec<Self> = Vec::with_capacity(len);

                while temp != 0 {
                    ret.push(Self(temp & mask));
                    temp >>= bits;
                }

                ret.resize(len, #name(0));

                ret
            }

            #[inline]
            fn mul_scalar(&self, scalar: Self::Scalar) -> Self {
                Self(self.0.wrapping_mul(scalar) & #mask)
            }
        }
    }
}
