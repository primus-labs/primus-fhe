use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result, Type};

use crate::{
    ast::Input,
    basic::{basic, display, impl_deser, impl_one, impl_ser, impl_zero},
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

            const ONE: Self = Self(1);

            const ZERO: Self = Self(0);

            const NEG_ONE: Self = Self(#modulus - 1);

            const MODULUS_VALUE: Self::Value = #modulus;

            const TWICE_MODULUS_VALUE: Self::Value = #modulus << 1;

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
