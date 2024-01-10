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
        impl algebra::Ring for #name {
            type Inner = #field_ty;

            type Order = #field_ty;

            const ONE: Self = #name(1);

            const ZERO: Self = #name(0);

            const NEG_ONE: Self = #name(#modulus - 1);

            const Q_DIV_8: Self = #name(#modulus >> 3);

            const Q3_DIV_8: Self = #name(3 * (#modulus >> 3));

            const Q7_DIV_8: Self = #name(7 * (#modulus >> 3));

            const NRG_Q_DIV_8: Self = #name(#modulus - (#modulus >> 3));

            const FOUR_INNER: Self::Inner = 4;

            const MODULUS_F64: f64 = #modulus as f64;

            #[doc = concat!("Creates a new [`", stringify!(#name), "`].")]
            #[inline]
            fn new(value: #field_ty) -> Self {
                Self(value)
            }

            #[inline]
            fn pow_of_two(pow: u32) -> Self {
                Self(1 << pow)
            }

            #[inline]
            fn mask(bits: u32) -> Self::Inner {
                #field_ty::MAX >> (#field_ty::BITS - bits)
            }

            #[inline]
            fn inner(self) -> #field_ty {
                self.0
            }

            #[inline]
            fn cast_into_usize(self) -> usize {
                num_traits::cast::<#field_ty, usize>(self.0).unwrap()
            }

            #[inline]
            fn cast_from_usize(value: usize) -> Self {
                Self::new(num_traits::cast::<usize, #field_ty>(value).unwrap())
            }

            #[inline]
            fn as_f64(self) -> f64 {
                self.0 as f64
            }

            #[inline]
            fn from_f64(value: f64) -> Self {
                Self::new(value as #field_ty)
            }

            #[inline]
            fn modulus_value() -> Self::Inner {
                #modulus
            }

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn decompose_len(basis: Self::Inner) -> usize {
                debug_assert!(basis.is_power_of_two() && basis > 1);
                algebra::div_ceil(<Self as algebra::ModulusConfig>::modulus().bit_count(), basis.trailing_zeros()) as usize
            }

            fn decompose(&self, basis: algebra::Basis<Self>) -> Vec<Self> {
                let mut temp = self.0;

                let len = basis.decompose_len();
                let mask = basis.mask();
                let bits = basis.bits();

                let mut ret: Vec<Self> = vec![#name(0); len];

                for v in ret.iter_mut() {
                    if temp == 0 {
                        break;
                    } else {
                        *v = Self(temp & mask);
                        temp >>= bits;
                    }
                }

                ret
            }

            fn decompose_at(&self, basis: algebra::Basis<Self>, dst: &mut [Self]) {
                let mut temp = self.0;

                let mask = basis.mask();
                let bits = basis.bits();

                for v in dst {
                    if temp == 0 {
                        break;
                    } else {
                        *v = Self(temp & mask);
                        temp >>= bits;
                    }
                }
            }

            fn decompose_at_mut(&mut self, dst: &mut Self, mask: Self::Inner, bits: u32) {
                *dst = Self(self.0 & mask);
                self.0 >>= bits;
            }

            #[inline]
            fn mul_scalar(&self, scalar: Self::Inner) -> Self {
                use algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(scalar, &<Self as algebra::ModulusConfig>::MODULUS))
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
        impl algebra::Ring for #name {
            type Inner = #field_ty;

            type Order = #field_ty;

            const ONE: Self = #name(1);

            const ZERO: Self = #name(0);

            const NEG_ONE: Self = #name(#mask);

            const Q_DIV_8: Self = #name(#modulus >> 3);

            const Q3_DIV_8: Self = #name(3 * (#modulus >> 3));

            const Q7_DIV_8: Self = #name(7 * (#modulus >> 3));

            const NRG_Q_DIV_8: Self = #name(#modulus - (#modulus >> 3));

            const FOUR_INNER: Self::Inner = 4;

            const MODULUS_F64: f64 = #modulus as f64;

            #[doc = concat!("Creates a new [`", stringify!(#name), "`].")]
            #[inline]
            fn new(value: #field_ty) -> Self {
                Self(value)
            }

            #[inline]
            fn pow_of_two(pow: u32) -> Self {
                Self(1 << pow)
            }

            #[inline]
            fn mask(bits: u32) -> Self::Inner {
                #field_ty::MAX >> (#field_ty::BITS - bits)
            }

            #[inline]
            fn inner(self) -> #field_ty {
                self.0
            }

            #[inline]
            fn cast_into_usize(self) -> usize {
                num_traits::cast::<#field_ty, usize>(self.0).unwrap()
            }

            #[inline]
            fn cast_from_usize(value: usize) -> Self {
                Self::new(num_traits::cast::<usize, #field_ty>(value).unwrap())
            }

            #[inline]
            fn as_f64(self) -> f64 {
                self.0 as f64
            }

            #[inline]
            fn from_f64(value: f64) -> Self {
                Self::new(value as #field_ty)
            }

            #[inline]
            fn modulus_value() -> Self::Inner {
                #modulus
            }

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn decompose_len(basis: Self::Inner) -> usize {
                debug_assert!(basis.is_power_of_two() && basis > 1);
                algebra::div_ceil(Self::modulus_value().trailing_zeros(), basis.trailing_zeros()) as usize
            }

            fn decompose(&self, basis: algebra::Basis<Self>) -> Vec<Self> {
                let mut temp = self.0;

                let len = basis.decompose_len();
                let mask = basis.mask();
                let bits = basis.bits();

                let mut ret: Vec<Self> = vec![#name(0); len];

                for v in ret.iter_mut() {
                    if temp == 0 {
                        break;
                    } else {
                        *v = Self(temp & mask);
                        temp >>= bits;
                    }
                }

                ret
            }

            fn decompose_at(&self, basis: algebra::Basis<Self>, dst: &mut [Self]) {
                let mut temp = self.0;

                let mask = basis.mask();
                let bits = basis.bits();

                for v in dst {
                    if temp == 0 {
                        break;
                    } else {
                        *v = Self(temp & mask);
                        temp >>= bits;
                    }
                }
            }

            fn decompose_at_mut(&mut self, dst: &mut Self, mask: Self::Inner, bits: u32) {
                *dst = Self(self.0 & mask);
                self.0 >>= bits;
            }

            #[inline]
            fn mul_scalar(&self, scalar: Self::Inner) -> Self {
                Self(self.0.wrapping_mul(scalar) & #mask)
            }
        }
    }
}
