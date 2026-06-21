use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

pub(crate) fn impl_reduce_ops(name: &Ident, modulus: &TokenStream, ty: &syn::Path) -> TokenStream {
    quote! {
        impl ::primus_modulus::reduce::Reduce<#ty> for #name {
            type Output = #ty;

            /// Calculates `value (mod modulus)`.
            #[inline(always)]
            fn reduce(self, value: #ty) -> Self::Output {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::common::compact;
                compact::reduce_once(#modulus, self.lazy_reduce(value))
            }
        }

        impl ::primus_modulus::reduce::Reduce<[#ty; 2]> for #name {
            type Output = #ty;

            /// Calculates `value (mod modulus)`.
            #[inline(always)]
            fn reduce(self, value: [#ty; 2]) -> Self::Output {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::common::compact;
                compact::reduce_once(#modulus, self.lazy_reduce(value))
            }
        }

        impl ::primus_modulus::reduce::Reduce<(#ty, #ty)> for #name {
            type Output = #ty;

            /// Calculates `value (mod modulus)`.
            #[inline(always)]
            fn reduce(self, value: (#ty, #ty)) -> Self::Output {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::common::compact;
                compact::reduce_once(#modulus, self.lazy_reduce(value))
            }
        }

        impl ::primus_modulus::reduce::Reduce<&[#ty]> for #name {
            type Output = #ty;

            /// Calculates `value (mod modulus)` when value's length > 0.
            #[inline(always)]
            fn reduce(self, value: &[#ty]) -> Self::Output {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::common::compact;
                compact::reduce_once(#modulus, self.lazy_reduce(value))
            }
        }

        impl ::primus_modulus::reduce::ReduceAssign<#ty> for #name {
            /// Calculates `value (mod modulus)`.
            #[inline]
            fn reduce_assign(self, value: &mut #ty) {
                use ::primus_modulus::reduce::Reduce;
                *value = self.reduce(*value);
            }
        }

        impl ::primus_modulus::reduce::ReduceOnce<#ty> for #name {
            type Output = #ty;

            #[inline(always)]
            fn reduce_once(self, value: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::reduce_once(#modulus, value)
            }
        }

        impl ::primus_modulus::reduce::ReduceOnceAssign<#ty> for #name {
            #[inline(always)]
            fn reduce_once_assign(self, value: &mut #ty) {
                use ::primus_modulus::common::compact;
                compact::reduce_once_assign(#modulus, value);
            }
        }

        impl ::primus_modulus::reduce::ReduceAdd<#ty> for #name {
            type Output = #ty;

            #[inline(always)]
            fn reduce_add(self, a: #ty, b: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::reduce_add(#modulus, a, b)
            }
        }

        impl ::primus_modulus::reduce::ReduceAddAssign<#ty> for #name {
            #[inline(always)]
            fn reduce_add_assign(self, a: &mut #ty, b: #ty) {
                use ::primus_modulus::common::compact;
                compact::reduce_add_assign(#modulus, a, b);
            }
        }

        impl ::primus_modulus::reduce::ReduceDouble<#ty> for #name {
            type Output = #ty;

            #[inline(always)]
            fn reduce_double(self, value: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::reduce_double(#modulus, value)
            }
        }

        impl ::primus_modulus::reduce::ReduceDoubleAssign<#ty> for #name {
            #[inline(always)]
            fn reduce_double_assign(self, value: &mut #ty) {
                use ::primus_modulus::common::compact;
                compact::reduce_double_assign(#modulus, value);
            }
        }

        impl ::primus_modulus::reduce::ReduceSub<#ty> for #name {
            type Output = #ty;

            #[inline(always)]
            fn reduce_sub(self, a: #ty, b: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::reduce_sub(#modulus, a, b)
            }
        }

        impl ::primus_modulus::reduce::ReduceSubAssign<#ty> for #name {
            #[inline(always)]
            fn reduce_sub_assign(self, a: &mut #ty, b: #ty) {
                use ::primus_modulus::common::compact;
                compact::reduce_sub_assign(#modulus, a, b);
            }
        }

        impl ::primus_modulus::reduce::ReduceNeg<#ty> for #name {
            type Output = #ty;

            #[inline(always)]
            fn reduce_neg(self, value: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::reduce_neg(#modulus, value)
            }
        }

        impl ::primus_modulus::reduce::ReduceNegAssign<#ty> for #name {
            #[inline(always)]
            fn reduce_neg_assign(self, value: &mut #ty) {
                use ::primus_modulus::common::compact;
                compact::reduce_neg_assign(#modulus, value);
            }
        }

        impl ::primus_modulus::reduce::ReduceMul<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn reduce_mul(self, a: #ty, b: #ty) -> Self::Output {
                use ::primus_modulus::reduce::Reduce;
                use ::primus_modulus::integer::WideningMul;
                self.reduce(WideningMul::widening_mul(a, b))
            }
        }

        impl ::primus_modulus::reduce::ReduceMulAssign<#ty> for #name {
            #[inline]
            fn reduce_mul_assign(self, a: &mut #ty, b: #ty) {
                use ::primus_modulus::reduce::Reduce;
                use ::primus_modulus::integer::WideningMul;
                *a = self.reduce(WideningMul::widening_mul(*a, b));
            }
        }

        impl ::primus_modulus::reduce::ReduceSquare<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn reduce_square(self, value: #ty) -> Self::Output {
                use ::primus_modulus::reduce::Reduce;
                use ::primus_modulus::integer::WideningMul;
                self.reduce(WideningMul::widening_mul(value, value))
            }
        }

        impl ::primus_modulus::reduce::ReduceSquareAssign<#ty> for #name {
            #[inline]
            fn reduce_square_assign(self, value: &mut #ty) {
                use ::primus_modulus::reduce::Reduce;
                use ::primus_modulus::integer::WideningMul;
                *value = self.reduce(WideningMul::widening_mul(*value, *value));
            }
        }

        impl ::primus_modulus::reduce::ReduceMulAdd<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn reduce_mul_add(self, a: #ty, b: #ty, c: #ty) -> Self::Output {
                use ::primus_modulus::reduce::Reduce;
                use ::primus_modulus::integer::CarryingMul;
                self.reduce(CarryingMul::carrying_mul(a, b, c))
            }
        }

        impl ::primus_modulus::reduce::ReduceMulAddAssign<#ty> for #name {
            #[inline]
            fn reduce_mul_add_assign(self, a: &mut #ty, b: #ty, c: #ty) {
                use ::primus_modulus::reduce::Reduce;
                use ::primus_modulus::integer::CarryingMul;
                *a = self.reduce(CarryingMul::carrying_mul(*a, b, c));
            }
        }

        impl ::primus_modulus::reduce::TryReduceInv<#ty> for #name {
            type Output = #ty;

            #[inline(always)]
            fn try_reduce_inv(self, value: #ty) -> Result<Self::Output, ::primus_modulus::reduce::ReduceError<#ty>> {
                use ::primus_modulus::common::compact;
                compact::try_reduce_inv(#modulus, value)
            }
        }

        impl ::primus_modulus::reduce::ReduceInv<#ty> for #name {
            type Output = #ty;

            #[inline(always)]
            fn reduce_inv(self, value: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::reduce_inv(#modulus, value)
            }
        }

        impl ::primus_modulus::reduce::ReduceInvAssign<#ty> for #name {
            #[inline(always)]
            fn reduce_inv_assign(self, value: &mut #ty) {
                use ::primus_modulus::common::compact;
                compact::reduce_inv_assign(#modulus, value);
            }
        }

        impl ::primus_modulus::reduce::ReduceDiv<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn reduce_div(self, a: #ty, b: #ty) -> Self::Output {
                use ::primus_modulus::reduce::{ReduceMul, ReduceInv};
                self.reduce_mul(a, self.reduce_inv(b))
            }
        }

        impl ::primus_modulus::reduce::ReduceDivAssign<#ty> for #name {
            #[inline]
            fn reduce_div_assign(self, a: &mut #ty, b: #ty) {
                use ::primus_modulus::reduce::{ReduceMulAssign, ReduceInv};
                self.reduce_mul_assign(a, self.reduce_inv(b));
            }
        }

        impl ::primus_modulus::reduce::ReduceExp<#ty> for #name{
            #[inline]
            fn reduce_exp<E: ::primus_modulus::integer::UnsignedInteger>(self, base: #ty, mut exp: E) -> #ty {
                use ::primus_modulus::reduce::{ReduceSquareAssign, ReduceMulAssign};
                if exp.is_zero() {
                    return 1;
                }

                if base == 0 {
                    return 0;
                }

                debug_assert!(base < #modulus);

                let mut power: #ty = base;

                let exp_trailing_zeros = exp.trailing_zeros();
                if exp_trailing_zeros > 0 {
                    for _ in 0..exp_trailing_zeros {
                        self.reduce_square_assign(&mut power);
                    }
                    exp >>= exp_trailing_zeros;
                }

                if exp.is_one() {
                    return power;
                }

                let mut intermediate: #ty = power;
                for _ in 1..(E::BITS - exp.leading_zeros()) {
                    exp >>= 1;
                    self.reduce_square_assign(&mut power);
                    if !(exp & E::ONE).is_zero() {
                        self.reduce_mul_assign(&mut intermediate, power);
                    }
                }
                intermediate
            }
        }

        impl ::primus_modulus::reduce::ReduceExpPowOf2<#ty> for #name {
            #[inline]
            fn reduce_exp_power_of_2(self, base: #ty, exp_log: u32) -> #ty {
                use ::primus_modulus::reduce::ReduceSquareAssign;
                if base == 0 {
                    return 0;
                }

                let mut power = base;

                for _ in 0..exp_log {
                    self.reduce_square_assign(&mut power);
                }

                power
            }
        }

        impl ::primus_modulus::reduce::ReduceDotProduct<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn reduce_dot_product(self, a: impl AsRef<[#ty]>, b: impl AsRef<[#ty]>) -> #ty {
                use ::primus_modulus::reduce::*;
                /// `c += a * b`
                fn multiply_add(c: &mut [#ty; 2], a: #ty, b: #ty) {
                    use ::primus_modulus::integer::{CarryingAdd, WideningMul};
                    let (lw, hw) = WideningMul::widening_mul(a, b);
                    let carry;
                    (c[0], carry) = c[0].overflowing_add(lw);
                    (c[1], _) = CarryingAdd::carrying_add(c[1], hw, carry);
                }

                let a = a.as_ref();
                let b = b.as_ref();

                assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");

                let mut a_iter = a.chunks_exact(16);
                let mut b_iter = b.chunks_exact(16);

                let inter = (&mut a_iter)
                    .zip(&mut b_iter)
                    .map(|(a_s, b_s)| {
                        let mut c: [#ty; 2] = [0, 0];
                        for (&a, &b) in a_s.iter().zip(b_s) {
                            multiply_add(&mut c, a, b);
                        }
                        self.reduce(c)
                    })
                    .fold(0, |acc: #ty, b| self.reduce_add(acc, b));

                let mut c: [#ty; 2] = [0, 0];
                a_iter
                    .remainder()
                    .iter()
                    .zip(b_iter.remainder())
                    .for_each(|(&a, &b)| {
                        multiply_add(&mut c, a, b);
                    });
                self.reduce_add(self.reduce(c), inter)
            }

            #[inline]
            fn reduce_dot_product_iter(
                self,
                a: impl IntoIterator<Item = #ty>,
                b: impl IntoIterator<Item = #ty>,
            ) -> #ty {
                use ::primus_modulus::reduce::*;
                /// `c += a * b`
                fn multiply_add(c: &mut [#ty; 2], a: #ty, b: #ty) {
                    use ::primus_modulus::integer::{CarryingAdd, WideningMul};
                    let (lw, hw) = WideningMul::widening_mul(a, b);
                    let carry;
                    (c[0], carry) = c[0].overflowing_add(lw);
                    (c[1], _) = CarryingAdd::carrying_add(c[1], hw, carry);
                }

                let mut a_iter = a.into_iter();
                let mut b_iter = b.into_iter();

                let mut a_temp_array = [0; 16];
                let mut b_temp_array = [0; 16];

                let mut i = 0;
                let mut result = 0;

                while let (Some(a_next), Some(b_next)) = (a_iter.next(), b_iter.next()) {
                    if i < 16 {
                        a_temp_array[i] = a_next;
                        b_temp_array[i] = b_next;
                        i += 1;
                    } else {
                        let mut c: [#ty; 2] = [0, 0];
                        for (&a, b) in a_temp_array.iter().zip(b_temp_array) {
                            multiply_add(&mut c, a, b);
                        }
                        self.reduce_add_assign(&mut result, self.reduce(c));

                        a_temp_array.fill(0);
                        b_temp_array.fill(0);
                        a_temp_array[0] = a_next;
                        b_temp_array[0] = b_next;
                        i = 1;
                    }
                }

                let mut c: [#ty; 2] = [0, 0];
                for (&a, &b) in a_temp_array[..i].iter().zip(b_temp_array[..i].iter()) {
                    multiply_add(&mut c, a, b);
                }
                self.reduce_add_assign(&mut result, self.reduce(c));

                result
            }
        }

    }
}
