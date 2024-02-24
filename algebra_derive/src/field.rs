use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, LitInt, Result, Type};

use crate::{
    ast::Input,
    basic::{basic, display, impl_one, impl_zero},
    ops::*,
};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_field_with_ops(input))
}

fn impl_field_with_ops(input: Input) -> TokenStream {
    let name = &input.ident;
    let field_ty = input.field.ty;
    let modulus = input.attrs.modulus.unwrap();

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

        #impl_div

        #impl_inv

        #impl_field
    }
}

#[inline]
fn impl_field(name: &proc_macro2::Ident, field_ty: &Type, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::algebra::Field for #name {
            type Inner = #field_ty;

            type Order = #field_ty;

            const ONE: Self = #name(1);

            const ZERO: Self = #name(0);

            const NEG_ONE: Self = #name(#modulus - 1);

            const ONE_INNER: Self::Inner = 1;

            const ZERO_INNER: Self::Inner = 0;

            const Q_DIV_8: Self = #name(#modulus >> 3);

            const NRG_Q_DIV_8: Self = #name(#modulus - (#modulus >> 3));

            const MODULUS_F64: f64 = #modulus as f64;

            #[doc = concat!("Creates a new [`", stringify!(#name), "`].")]
            #[inline]
            fn new(value: #field_ty) -> Self {
                Self(value)
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
                ::algebra::div_ceil(<Self as ::algebra::ModulusConfig>::modulus().bit_count(), basis.trailing_zeros()) as usize
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
                    } else {
                        *v = Self(temp & mask);
                        temp >>= bits;
                    }
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
                    } else {
                        *v = Self(temp & mask);
                        temp >>= bits;
                    }
                }
            }

            #[inline]
            fn decompose_lsb_bits(&mut self, mask: Self::Inner, bits: u32) -> Self {
                let temp = Self(self.0 & mask);
                self.0 >>= bits;
                temp
            }

            #[inline]
            fn decompose_lsb_bits_at(&mut self, destination: &mut Self, mask: Self::Inner, bits: u32) {
                *destination = Self(self.0 & mask);
                self.0 >>= bits;
            }

            #[inline]
            fn mul_scalar(self, scalar: Self::Inner) -> Self {
                use ::algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(scalar, &<Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn add_mul(self, a: Self, b: Self) -> Self {
                use ::algebra::Widening;
                use ::algebra::reduce::Reduce;
                Self(a.0.carry_mul(b.0, self.0).reduce(&<Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn mul_add(self, a: Self, b: Self) -> Self {
                use ::algebra::Widening;
                use ::algebra::reduce::Reduce;
                Self(self.0.carry_mul(a.0, b.0).reduce(&<Self as ::algebra::ModulusConfig>::MODULUS))
            }

            #[inline]
            fn add_mul_assign(&mut self, a: Self, b: Self) {
                use ::algebra::Widening;
                use ::algebra::reduce::Reduce;
                self.0 = a.0.carry_mul(b.0, self.0).reduce(&<Self as ::algebra::ModulusConfig>::MODULUS);
            }

            #[inline]
            fn mul_add_assign(&mut self, a: Self, b: Self) {
                use ::algebra::Widening;
                use ::algebra::reduce::Reduce;
                self.0 = self.0.carry_mul(a.0, b.0).reduce(&<Self as ::algebra::ModulusConfig>::MODULUS);
            }
        }
    }
}
