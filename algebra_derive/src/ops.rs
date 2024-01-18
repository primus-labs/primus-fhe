use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{LitInt, Type};

pub(crate) fn add_and_ops(name: &Ident, mask: &TokenStream) -> TokenStream {
    quote! {
        impl ::std::ops::Add<Self> for #name {
            type Output = Self;

            #[inline]
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn add(self, rhs: Self) -> Self::Output {
                Self(self.0.wrapping_add(rhs.0) & #mask)
            }
        }

        impl ::std::ops::Add<&Self> for #name {
            type Output = Self;

            #[inline]
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn add(self, rhs: &Self) -> Self::Output {
                Self(self.0.wrapping_add(rhs.0) & #mask)
            }
        }

        impl ::std::ops::AddAssign<Self> for #name {
            #[inline]
            #[allow(clippy::suspicious_op_assign_impl)]
            fn add_assign(&mut self, rhs: Self) {
                self.0 = self.0.wrapping_add(rhs.0) & #mask;
            }
        }

        impl ::std::ops::AddAssign<&Self> for #name {
            #[inline]
            #[allow(clippy::suspicious_op_assign_impl)]
            fn add_assign(&mut self, rhs: &Self) {
                self.0 = self.0.wrapping_add(rhs.0) & #mask;
            }
        }
    }
}

pub(crate) fn sub_and_ops(name: &Ident, mask: &TokenStream) -> TokenStream {
    quote! {
        impl ::std::ops::Sub<Self> for #name {
            type Output = Self;

            #[inline]
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn sub(self, rhs: Self) -> Self::Output {
                Self(self.0.wrapping_sub(rhs.0) & #mask)
            }
        }

        impl ::std::ops::Sub<&Self> for #name {
            type Output = Self;

            #[inline]
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn sub(self, rhs: &Self) -> Self::Output {
                Self(self.0.wrapping_sub(rhs.0) & #mask)
            }
        }

        impl ::std::ops::SubAssign<Self> for #name {
            #[inline]
            #[allow(clippy::suspicious_op_assign_impl)]
            fn sub_assign(&mut self, rhs: Self) {
                self.0 = self.0.wrapping_sub(rhs.0) & #mask;
            }
        }

        impl ::std::ops::SubAssign<&Self> for #name {
            #[inline]
            #[allow(clippy::suspicious_op_assign_impl)]
            fn sub_assign(&mut self, rhs: &Self) {
                self.0 = self.0.wrapping_sub(rhs.0) & #mask;
            }
        }
    }
}

pub(crate) fn mul_and_ops(name: &Ident, mask: &TokenStream) -> TokenStream {
    quote! {
        impl ::std::ops::Mul<Self> for #name {
            type Output = Self;

            #[inline]
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn mul(self, rhs: Self) -> Self::Output {
                Self(self.0.wrapping_mul(rhs.0) & #mask)
            }
        }

        impl ::std::ops::Mul<&Self> for #name {
            type Output = Self;

            #[inline]
            #[allow(clippy::suspicious_arithmetic_impl)]
            fn mul(self, rhs: &Self) -> Self::Output {
                Self(self.0.wrapping_mul(rhs.0) & #mask)
            }
        }

        impl ::std::ops::MulAssign<Self> for #name {
            #[inline]
            #[allow(clippy::suspicious_op_assign_impl)]
            fn mul_assign(&mut self, rhs: Self) {
                self.0 = self.0.wrapping_mul(rhs.0) & #mask;
            }
        }

        impl ::std::ops::MulAssign<&Self> for #name {
            #[inline]
            #[allow(clippy::suspicious_op_assign_impl)]
            fn mul_assign(&mut self, rhs: &Self) {
                self.0 = self.0.wrapping_mul(rhs.0) & #mask;
            }
        }
    }
}

pub(crate) fn neg_and_ops(name: &Ident, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::std::ops::Neg for #name {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self::Output {
                Self(#modulus - self.0)
            }
        }
    }
}

pub(crate) fn pow_and_ops(
    name: &Ident,
    field_ty: &Type,
    modulus: &LitInt,
    mask: &TokenStream,
) -> TokenStream {
    quote! {
        impl num_traits::Pow<<Self as algebra::Ring>::Order> for #name {
            type Output = Self;

            #[inline]
            fn pow(self, mut exp: <Self as algebra::Ring>::Order) -> Self::Output {
                if exp == 0 {
                    return Self(1);
                }

                debug_assert!(self.0 < #modulus);

                let mut power: #field_ty = self.0;

                let exp_trailing_zeros = exp.trailing_zeros();
                if exp_trailing_zeros > 0 {
                    for _ in 0..exp_trailing_zeros {
                        power = power.wrapping_mul(power) & #mask;
                    }
                    exp >>= exp_trailing_zeros;
                }

                if exp == 1 {
                    return Self(power);
                }

                let mut intermediate: #field_ty = power;
                for _ in 1..(#field_ty::BITS - exp.leading_zeros()) {
                    exp >>= 1;
                    power = power.wrapping_mul(power) & #mask;
                    if (exp & 1) != 0 {
                        intermediate = intermediate.wrapping_mul(power) & #mask;
                    }
                }
                Self(intermediate)
            }
        }
    }
}

pub(crate) fn barrett(name: &Ident, field_ty: &Type, modulus: &LitInt) -> TokenStream {
    quote! {
        impl algebra::ModulusConfig for #name {
            type Modulus = algebra::modulus::BarrettModulus<#field_ty>;
            const MODULUS: Self::Modulus = Self::Modulus::new(#modulus);
        }
    }
}

pub(crate) fn add_reduce_ops(name: &Ident, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::std::ops::Add<Self> for #name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: Self) -> Self::Output {
                use algebra::reduce::AddReduce;
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::Add<&Self> for #name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: &Self) -> Self::Output {
                use algebra::reduce::AddReduce;
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::AddAssign<Self> for #name {
            #[inline]
            fn add_assign(&mut self, rhs: Self) {
                use algebra::reduce::AddReduceAssign;
                self.0.add_reduce_assign(rhs.0, #modulus)
            }
        }

        impl ::std::ops::AddAssign<&Self> for #name {
            #[inline]
            fn add_assign(&mut self, rhs: &Self) {
                use algebra::reduce::AddReduceAssign;
                self.0.add_reduce_assign(rhs.0, #modulus)
            }
        }
    }
}

pub(crate) fn sub_reduce_ops(name: &Ident, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::std::ops::Sub<Self> for #name {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: Self) -> Self::Output {
                use algebra::reduce::SubReduce;
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::Sub<&Self> for #name {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: &Self) -> Self::Output {
                use algebra::reduce::SubReduce;
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::SubAssign<Self> for #name {
            #[inline]
            fn sub_assign(&mut self, rhs: Self) {
                use algebra::reduce::SubReduceAssign;
                self.0.sub_reduce_assign(rhs.0, #modulus)
            }
        }

        impl ::std::ops::SubAssign<&Self> for #name {
            #[inline]
            fn sub_assign(&mut self, rhs: &Self) {
                use algebra::reduce::SubReduceAssign;
                self.0.sub_reduce_assign(rhs.0, #modulus)
            }
        }
    }
}

pub(crate) fn mul_reduce_ops(name: &Ident) -> TokenStream {
    quote! {
        impl ::std::ops::Mul<Self> for #name {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: Self) -> Self::Output {
                use algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::Mul<&Self> for #name {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: &Self) -> Self::Output {
                use algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::MulAssign<Self> for #name {
            #[inline]
            fn mul_assign(&mut self, rhs: Self) {
                use algebra::reduce::MulReduceAssign;
                self.0.mul_reduce_assign(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS)
            }
        }

        impl ::std::ops::MulAssign<&Self> for #name {
            #[inline]
            fn mul_assign(&mut self, rhs: &Self) {
                use algebra::reduce::MulReduceAssign;
                self.0.mul_reduce_assign(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS)
            }
        }
    }
}

pub(crate) fn neg_reduce_ops(name: &Ident, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::std::ops::Neg for #name {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self::Output {
                use algebra::reduce::NegReduce;
                Self(self.0.neg_reduce(#modulus))
            }
        }
    }
}

pub(crate) fn pow_reduce_ops(name: &Ident) -> TokenStream {
    quote! {
        impl num_traits::Pow<<Self as algebra::Ring>::Order> for #name {
            type Output = Self;

            #[inline]
            fn pow(self, rhs: <Self as algebra::Ring>::Order) -> Self::Output {
                use algebra::reduce::PowReduce;
                Self(self.0.pow_reduce(rhs, &<Self as algebra::ModulusConfig>::MODULUS))
            }
        }
    }
}

pub(crate) fn div_reduce_ops(name: &Ident) -> TokenStream {
    quote! {
        impl ::std::ops::Div<Self> for #name {
            type Output = Self;

            #[inline]
            fn div(self, rhs: Self) -> Self::Output {
                use algebra::reduce::DivReduce;
                Self(self.0.div_reduce(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::Div<&Self> for #name {
            type Output = Self;

            #[inline]
            fn div(self, rhs: &Self) -> Self::Output {
                use algebra::reduce::DivReduce;
                Self(self.0.div_reduce(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::DivAssign<Self> for #name {
            #[inline]
            fn div_assign(&mut self, rhs: Self) {
                use algebra::reduce::DivReduceAssign;
                self.0.div_reduce_assign(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS)
            }
        }

        impl ::std::ops::DivAssign<&Self> for #name {
            #[inline]
            fn div_assign(&mut self, rhs: &Self) {
                use algebra::reduce::DivReduceAssign;
                self.0.div_reduce_assign(rhs.0, &<Self as algebra::ModulusConfig>::MODULUS)
            }
        }
    }
}

pub(crate) fn inv_reduce_ops(name: &Ident, modulus: &LitInt) -> TokenStream {
    quote! {
        impl num_traits::Inv for #name {
            type Output = Self;

            #[inline]
            fn inv(self) -> Self::Output {
                use algebra::reduce::InvReduce;
                Self(self.0.inv_reduce(#modulus))
            }
        }
    }
}
