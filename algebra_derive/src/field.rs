use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{DeriveInput, Error, LitInt, Result, Type};

use crate::{
    ast::Input,
    basic::{basic, display, impl_one, impl_zero},
    ops::*,
};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    impl_field_with_ops(input)
}

fn impl_field_with_ops(input: Input) -> Result<TokenStream> {
    let name = &input.ident;
    let field_ty = input.field.ty;
    let modulus = input.attrs.modulus.unwrap();

    match field_ty {
        Type::Path(type_path) => {
            if type_path.clone().into_token_stream().to_string() == "u8" {
                let modulus_number: u8 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u8 type.",
                    )
                })?;
                if modulus_number.leading_zeros() < 2 {
                    return Err(Error::new_spanned(
                        input.field.original,
                        "Modulus is too big! It should be smaller than `u8::MAX >> 2`. You can also use `u16` for inner value.",
                    ));
                }
            } else if type_path.clone().into_token_stream().to_string() == "u16" {
                let modulus_number: u16 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u16 type.",
                    )
                })?;
                if modulus_number.leading_zeros() < 2 {
                    return Err(Error::new_spanned(
                        input.field.original,
                        "Modulus is too big! It should be smaller than `u16::MAX >> 2`. You can also use `u32` for inner value.",
                    ));
                }
            } else if type_path.clone().into_token_stream().to_string() == "u32" {
                let modulus_number: u32 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u32 type.",
                    )
                })?;
                if modulus_number.leading_zeros() < 2 {
                    return Err(Error::new_spanned(
                        input.field.original,
                        "Modulus is too big! It should be smaller than `u32::MAX >> 2`. You can also use `u64` for inner value.",
                    ));
                }
            } else if type_path.clone().into_token_stream().to_string() == "u64" {
                let modulus_number: u64 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        input.field.original,
                        "It's not possible to parse modulus into u64 type.",
                    )
                })?;
                if modulus_number.leading_zeros() < 2 {
                    return Err(Error::new_spanned(
                        input.field.original,
                        "Modulus is too big! It should be smaller than `u64::MAX >> 2`.",
                    ));
                }
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
    }

    let impl_basic = basic(name, field_ty, &modulus);

    let impl_display = display(name, &modulus);

    let impl_zero = impl_zero(name);

    let impl_one = impl_one(name);

    let impl_barrett = barrett(name, field_ty, &modulus);

    let impl_add = add_reduce_ops(name, &modulus);

    let impl_sub = sub_reduce_ops(name, &modulus);

    let impl_mul = mul_reduce_ops(name);

    let impl_neg = neg_reduce_ops(name, &modulus);

    let impl_pow = pow_reduce_ops(name);

    let impl_div = div_reduce_ops(name);

    let impl_inv = inv_reduce_ops(name, &modulus);

    let impl_field = impl_field(name, field_ty, &modulus);

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

        #impl_div

        #impl_inv

        #impl_field
    })
}

#[inline]
fn impl_field(name: &proc_macro2::Ident, field_ty: &Type, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::algebra::Field for #name {
            type Value = #field_ty;

            type Order = #field_ty;

            const ONE: Self = Self(1);

            const ZERO: Self = Self(0);

            const NEG_ONE: Self = Self(#modulus - 1);

            const ONE_INNER: Self::Value = 1;

            const MODULUS_INNER: Self::Value = #modulus;

            const TWICE_MODULUS_INNER: Self::Value = #modulus << 1;

            const Q_DIV_8: Self = Self(#modulus >> 3);

            const NEG_Q_DIV_8: Self = Self(#modulus - (#modulus >> 3));

            #[doc = concat!("Creates a new [`", stringify!(#name), "`].")]
            #[inline]
            fn new(value: #field_ty) -> Self {
                Self(value)
            }

            #[inline]
            fn checked_new(value: Self::Value) -> Self {
                if value < #modulus {
                    Self(value)
                } else {
                    use ::algebra::reduce::Reduce;
                    Self(value.reduce(<Self as ::algebra::ModulusConfig>::MODULUS))
                }
            }

            #[inline]
            fn get(self) -> #field_ty {
                self.0
            }

            #[inline]
            fn set(&mut self, value: Self::Value) {
                self.0 = value;
            }

            #[inline]
            fn checked_set(&mut self, value: Self::Value) {
                if value < #modulus {
                    self.0 = value;
                } else {
                    use ::algebra::reduce::ReduceAssign;
                    self.0.reduce_assign(<Self as ::algebra::ModulusConfig>::MODULUS);
                }
            }

            #[inline]
            fn modulus_value() -> Self::Value {
                #modulus
            }

            #[inline]
            fn normalize(self) -> Self {
                if self.0 >= #modulus {
                    Self(self.0 - #modulus)
                } else {
                    self
                }
            }

            #[inline]
            fn normalize_assign(&mut self) {
                if self.0 >= #modulus {
                    self.0 -= #modulus;
                }
            }

            #[inline]
            fn mul_scalar(self, scalar: Self::Value) -> Self {
                use ::algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(scalar, <Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn add_mul(self, a: Self, b: Self) -> Self {
                use ::algebra::Widening;
                use ::algebra::reduce::Reduce;
                Self(a.0.carry_mul(b.0, self.0).reduce(<Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn add_mul_assign(&mut self, a: Self, b: Self) {
                use ::algebra::Widening;
                use ::algebra::reduce::Reduce;
                self.0 = a.0.carry_mul(b.0, self.0).reduce(<Self as ::algebra::ModulusConfig>::MODULUS);
            }

            #[inline]
            fn mul_fast(self, rhs: Self) -> Self {
                use ::algebra::reduce::LazyMulReduce;
                Self(self.0.lazy_mul_reduce(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn mul_assign_fast(&mut self, rhs: Self) {
                use ::algebra::reduce::LazyMulReduceAssign;
                self.0.lazy_mul_reduce_assign(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS)
            }

            #[inline]
            fn add_mul_fast(self, a: Self, b: Self) -> Self {
                use ::algebra::Widening;
                use ::algebra::reduce::LazyReduce;
                Self(a.0.carry_mul(b.0, self.0).lazy_reduce(<Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn add_mul_assign_fast(&mut self, a: Self, b: Self) {
                use ::algebra::Widening;
                use ::algebra::reduce::LazyReduce;
                self.0 = a.0.carry_mul(b.0, self.0).lazy_reduce(<Self as ::algebra::ModulusConfig>::MODULUS);
            }

            #[inline]
            fn cast_into_usize(self) -> usize {
                ::num_traits::cast::<#field_ty, usize>(self.0).unwrap()
            }

            #[inline]
            fn cast_from_usize(value: usize) -> Self {
                Self::new(::num_traits::cast::<usize, #field_ty>(value).unwrap())
            }

            #[inline]
            fn to_f64(self) -> f64 {
                self.0 as f64
            }

            #[inline]
            fn from_f64(value: f64) -> Self {
                Self::new(value as #field_ty)
            }

            #[inline]
            fn order() -> Self::Order {
                #modulus
            }

            #[inline]
            fn mask(bits: u32) -> Self::Value {
                #field_ty::MAX >> (#field_ty::BITS - bits)
            }

            #[inline]
            fn decompose_len(basis: Self::Value) -> usize {
                debug_assert!(basis.is_power_of_two() && basis > 1);
                ::algebra::div_ceil(<Self as ::algebra::ModulusConfig>::MODULUS.bit_count(), basis.trailing_zeros()) as usize
            }

            fn decompose(self, basis: ::algebra::Basis<Self>) -> Vec<Self> {
                let mut temp = self.0;

                let len = basis.decompose_len();
                let mask = basis.mask();
                let bits = basis.bits();

                let mut ret: Vec<Self> = vec![#name(0); len];

                for v in ret.iter_mut() {
                    if temp == 0 {
                        break;
                    }
                    *v = Self(temp & mask);
                    temp >>= bits;
                }

                ret
            }

            fn decompose_at(self, basis: ::algebra::Basis<Self>, destination: &mut [Self]) {
                let mut temp = self.0;

                let mask = basis.mask();
                let bits = basis.bits();

                for v in destination {
                    if temp == 0 {
                        break;
                    }
                    *v = Self(temp & mask);
                    temp >>= bits;
                }
            }

            #[inline]
            fn decompose_lsb_bits(&mut self, mask: Self::Value, bits: u32) -> Self {
                let temp = Self(self.0 & mask);
                self.0 >>= bits;
                temp
            }

            #[inline]
            fn decompose_lsb_bits_at(&mut self, destination: &mut Self, mask: Self::Value, bits: u32) {
                *destination = Self(self.0 & mask);
                self.0 >>= bits;
            }
        }
    }
}
