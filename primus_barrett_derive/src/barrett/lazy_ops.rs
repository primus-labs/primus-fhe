use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

pub(crate) fn impl_lazy_reduce_ops(
    name: &Ident,
    modulus: &TokenStream,
    ty: &syn::Path,
    ratio: &[TokenStream; 2],
) -> TokenStream {
    let [r0, r1] = ratio;
    quote! {
        impl #name {
            /// Calculates `value (mod 2*modulus)`.
            #[inline]
            fn lazy_reduce_wide(self, lo: #ty, hi: #ty) -> #ty {
                use ::primus_modulus::integer::{CarryingMul, WideningMul};
                // Step 1.
                //                        ratio[1]  ratio[0]
                //                   *          hi        lo
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //                      +-------------------+
                //                      |         a         |    <-- lo * ratio[0]
                //                      +-------------------+
                //             +------------------+
                //             |        b         |              <-- lo * ratio[1]
                //             +------------------+
                //             +------------------+
                //             |        c         |              <-- hi * ratio[0]
                //             +------------------+
                //   +------------------+
                //   |        d         |                        <-- hi * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //             +--------+
                //             |   q₃   |
                //             +--------+
                let ah = lo.widening_mul_hw(#r0);

                let b = CarryingMul::carrying_mul(lo, #r1, ah);
                let c = WideningMul::widening_mul(hi, #r0);

                let d = hi.wrapping_mul(#r1);

                let bch = b.1.carrying_add(c.1, b.0.overflowing_add(c.0).1).0;

                let q = d.wrapping_add(bch);

                // Step 2.
                lo.wrapping_sub(q.wrapping_mul(#modulus))
            }
        }

        impl ::primus_modulus::reduce::LazyReduce<#ty> for #name {
            type Output = #ty;

            /// Calculates `value (mod 2*modulus)`.
            #[inline]
            fn lazy_reduce(self, value: #ty) -> #ty {
                use ::primus_modulus::integer::{CarryingMul, WideningMul};
                // Step 1.
                //              ratio[1]  ratio[0]
                //         *               value
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //            +-------------------+
                //            |  tmp1   |         |    <-- value * ratio[0]
                //            +-------------------+
                //   +------------------+
                //   |      tmp2        |              <-- value * ratio[1]
                //   +------------------+
                //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                //   +--------+
                //   |   q₃   |
                //   +--------+
                let tmp = value.widening_mul_hw(#r0); // tmp1
                let q = value.carrying_mul_hw(#r1, tmp); // q₃

                // Step 2.
                value.wrapping_sub(q.wrapping_mul(#modulus)) // r = r₁ - r₂
            }
        }

        impl ::primus_modulus::reduce::LazyReduce<[#ty; 2]> for #name {
            type Output = #ty;

            /// Calculates `value (mod 2*modulus)`.
            #[inline]
            fn lazy_reduce(self, value: [#ty; 2]) -> Self::Output {
                self.lazy_reduce_wide(value[0], value[1])
            }
        }

        impl ::primus_modulus::reduce::LazyReduce<(#ty, #ty)> for #name {
            type Output = #ty;

            /// Calculates `value (mod 2*modulus)`.
            #[inline]
            fn lazy_reduce(self, value: (#ty, #ty)) -> Self::Output {
                self.lazy_reduce_wide(value.0, value.1)
            }
        }

        impl ::primus_modulus::reduce::LazyReduce<&[#ty]> for #name {
            type Output = #ty;

            /// Calculates `value (mod 2*modulus)` when value's length > 0.
            #[inline]
            fn lazy_reduce(self, value: &[#ty]) -> Self::Output {
                match value {
                    &[] => unreachable!(),
                    &[v] => {
                        if v < #modulus << 1u32 {
                            v
                        } else {
                            self.lazy_reduce(v)
                        }
                    }
                    [other @ .., last] => other
                        .iter()
                        .rfold(*last, |acc, &x| self.lazy_reduce_wide(x, acc)),
                }
            }
        }

        impl ::primus_modulus::reduce::LazyReduceAssign<#ty> for #name {
            /// Calculates `value (mod 2*modulus)`.
            #[inline]
            fn lazy_reduce_assign(self, value: &mut #ty) {
                use ::primus_modulus::reduce::LazyReduce;
                *value = self.lazy_reduce(*value);
            }
        }

        impl ::primus_modulus::reduce::LazyReduceMul<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn lazy_reduce_mul(self, a: #ty, b: #ty) -> Self::Output {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::integer::WideningMul;
                self.lazy_reduce(WideningMul::widening_mul(a, b))
            }
        }

        impl ::primus_modulus::reduce::LazyReduceMulAssign<#ty> for #name {
            #[inline]
            fn lazy_reduce_mul_assign(self, a: &mut #ty, b: #ty) {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::integer::WideningMul;
                *a = self.lazy_reduce(WideningMul::widening_mul(*a, b));
            }
        }

        impl ::primus_modulus::reduce::LazyReduceMulAdd<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn lazy_reduce_mul_add(self, a: #ty, b: #ty, c: #ty) -> Self::Output {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::integer::CarryingMul;
                self.lazy_reduce(CarryingMul::carrying_mul(a, b, c))
            }
        }

        impl ::primus_modulus::reduce::LazyReduceMulAddAssign<#ty> for #name {
            #[inline]
            fn lazy_reduce_mul_add_assign(self, a: &mut #ty, b: #ty, c: #ty) {
                use ::primus_modulus::reduce::LazyReduce;
                use ::primus_modulus::integer::CarryingMul;
                *a = self.lazy_reduce(CarryingMul::carrying_mul(*a, b, c));
            }
        }

        impl ::primus_modulus::reduce::LazyReduceSub<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn lazy_reduce_sub(self, a: #ty, b: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::lazy_reduce_sub(#modulus, a, b)
            }
        }

        impl ::primus_modulus::reduce::LazyReduceSubAssign<#ty> for #name {
            #[inline]
            fn lazy_reduce_sub_assign(self, a: &mut #ty, b: #ty) {
                use ::primus_modulus::common::compact;
                compact::lazy_reduce_sub_assign(#modulus, a, b);
            }
        }

        impl ::primus_modulus::reduce::LazyReduceNeg<#ty> for #name {
            type Output = #ty;

            #[inline]
            fn lazy_reduce_neg(self, value: #ty) -> Self::Output {
                use ::primus_modulus::common::compact;
                compact::lazy_reduce_neg(#modulus, value)
            }
        }

        impl ::primus_modulus::reduce::LazyReduceNegAssign<#ty> for #name {
            #[inline]
            fn lazy_reduce_neg_assign(self, value: &mut #ty) {
                use ::primus_modulus::common::compact;
                compact::lazy_reduce_neg_assign(#modulus, value);
            }
        }
    }
}
