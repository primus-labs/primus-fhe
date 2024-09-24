use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::Type;

use crate::attr::ModulusType;

pub(crate) fn impl_modulus_config(
    name: &Ident,
    field_ty: &Type,
    modulus_type: ModulusType,
    modulus: &TokenStream,
) -> TokenStream {
    match modulus_type {
        ModulusType::Barrett => {
            quote! {
                impl ::algebra::ModulusConfig for #name {
                    type Modulus = ::algebra::modulus::BarrettModulus<#field_ty>;
                    const MODULUS: Self::Modulus = Self::Modulus::new(#modulus);
                }
            }
        }
    }
}

pub(crate) fn add_reduce_ops(name: &Ident, modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::std::ops::Add<Self> for #name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: Self) -> Self::Output {
                use ::algebra::reduce::AddReduce;
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::Add<&Self> for #name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: &Self) -> Self::Output {
                use ::algebra::reduce::AddReduce;
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::AddAssign<Self> for #name {
            #[inline]
            fn add_assign(&mut self, rhs: Self) {
                use ::algebra::reduce::AddReduceAssign;
                self.0.add_reduce_assign(rhs.0, #modulus)
            }
        }

        impl ::std::ops::AddAssign<&Self> for #name {
            #[inline]
            fn add_assign(&mut self, rhs: &Self) {
                use ::algebra::reduce::AddReduceAssign;
                self.0.add_reduce_assign(rhs.0, #modulus)
            }
        }
    }
}

pub(crate) fn sub_reduce_ops(name: &Ident, modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::std::ops::Sub<Self> for #name {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: Self) -> Self::Output {
                use ::algebra::reduce::SubReduce;
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::Sub<&Self> for #name {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: &Self) -> Self::Output {
                use ::algebra::reduce::SubReduce;
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::SubAssign<Self> for #name {
            #[inline]
            fn sub_assign(&mut self, rhs: Self) {
                use ::algebra::reduce::SubReduceAssign;
                self.0.sub_reduce_assign(rhs.0, #modulus)
            }
        }

        impl ::std::ops::SubAssign<&Self> for #name {
            #[inline]
            fn sub_assign(&mut self, rhs: &Self) {
                use ::algebra::reduce::SubReduceAssign;
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
                use ::algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::Mul<&Self> for #name {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: &Self) -> Self::Output {
                use ::algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::MulAssign<Self> for #name {
            #[inline]
            fn mul_assign(&mut self, rhs: Self) {
                use ::algebra::reduce::MulReduceAssign;
                self.0.mul_reduce_assign(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS)
            }
        }

        impl ::std::ops::MulAssign<&Self> for #name {
            #[inline]
            fn mul_assign(&mut self, rhs: &Self) {
                use ::algebra::reduce::MulReduceAssign;
                self.0.mul_reduce_assign(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS)
            }
        }
    }
}

pub(crate) fn neg_reduce_ops(name: &Ident, modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::std::ops::Neg for #name {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self::Output {
                use ::algebra::reduce::NegReduce;
                Self(self.0.neg_reduce(#modulus))
            }
        }
    }
}

pub(crate) fn pow_reduce_ops(name: &Ident) -> TokenStream {
    quote! {
        impl ::num_traits::Pow<<Self as ::algebra::Field>::Order> for #name {
            type Output = Self;

            #[inline]
            fn pow(self, rhs: <Self as ::algebra::Field>::Order) -> Self::Output {
                use ::algebra::reduce::ExpReduce;
                Self(self.0.exp_reduce(rhs, <Self as ::algebra::ModulusConfig>::MODULUS))
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
                use ::algebra::reduce::DivReduce;
                Self(self.0.div_reduce(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::Div<&Self> for #name {
            type Output = Self;

            #[inline]
            fn div(self, rhs: &Self) -> Self::Output {
                use ::algebra::reduce::DivReduce;
                Self(self.0.div_reduce(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS))
            }
        }

        impl ::std::ops::DivAssign<Self> for #name {
            #[inline]
            fn div_assign(&mut self, rhs: Self) {
                use ::algebra::reduce::DivReduceAssign;
                self.0.div_reduce_assign(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS)
            }
        }

        impl ::std::ops::DivAssign<&Self> for #name {
            #[inline]
            fn div_assign(&mut self, rhs: &Self) {
                use ::algebra::reduce::DivReduceAssign;
                self.0.div_reduce_assign(rhs.0, <Self as ::algebra::ModulusConfig>::MODULUS)
            }
        }
    }
}

pub(crate) fn inv_reduce_ops(name: &Ident, _modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::num_traits::Inv for #name {
            type Output = Self;

            #[inline]
            fn inv(self) -> Self::Output {
                // use ::algebra::reduce::InvReduce;
                // Self(self.0.inv_reduce(#modulus))
                use num_traits::Pow;
                self.pow(<Self as ::algebra::Field>::MODULUS_VALUE - 2)
            }
        }
    }
}
