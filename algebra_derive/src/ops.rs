use proc_macro2::{Ident, TokenStream};
use quote::quote;
use syn::{LitInt, Type};

pub(crate) fn barrett(name: &Ident, field_ty: &Type, modulus: &LitInt) -> TokenStream {
    quote! {
        impl algebra::field::BarrettConfig<#field_ty> for #name {
            const BARRETT_MODULUS: algebra::modulus::Modulus<#field_ty> = algebra::modulus::Modulus::<#field_ty>::new(#modulus);
        }
    }
}

pub(crate) fn add_reduce_ops(name: &Ident, modulus: &LitInt) -> TokenStream {
    quote! {
        impl ::std::ops::Add<Self> for #name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: Self) -> Self::Output {
                use algebra::modulo_traits::AddModulo;
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::Add<&Self> for #name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: &Self) -> Self::Output {
                use algebra::modulo_traits::AddModulo;
                Self(self.0.add_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::AddAssign<Self> for #name {
            #[inline]
            fn add_assign(&mut self, rhs: Self) {
                use algebra::modulo_traits::AddModuloAssign;
                self.0.add_reduce_assign(rhs.0, #modulus)
            }
        }

        impl ::std::ops::AddAssign<&Self> for #name {
            #[inline]
            fn add_assign(&mut self, rhs: &Self) {
                use algebra::modulo_traits::AddModuloAssign;
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
                use algebra::modulo_traits::SubModulo;
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::Sub<&Self> for #name {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: &Self) -> Self::Output {
                use algebra::modulo_traits::SubModulo;
                Self(self.0.sub_reduce(rhs.0, #modulus))
            }
        }

        impl ::std::ops::SubAssign<Self> for #name {
            #[inline]
            fn sub_assign(&mut self, rhs: Self) {
                use algebra::modulo_traits::SubModuloAssign;
                self.0.sub_reduce_assign(rhs.0, #modulus)
            }
        }

        impl ::std::ops::SubAssign<&Self> for #name {
            #[inline]
            fn sub_assign(&mut self, rhs: &Self) {
                use algebra::modulo_traits::SubModuloAssign;
                self.0.sub_reduce_assign(rhs.0, #modulus)
            }
        }
    }
}

pub(crate) fn mul_reduce_ops(name: &Ident, field_ty: &Type) -> TokenStream {
    quote! {
        impl ::std::ops::Mul<Self> for #name {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: Self) -> Self::Output {
                use algebra::modulo_traits::MulModulo;
                Self(self.0.mul_reduce(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS))
            }
        }

        impl ::std::ops::Mul<&Self> for #name {
            type Output = Self;

            #[inline]
            fn mul(self, rhs: &Self) -> Self::Output {
                use algebra::modulo_traits::MulModulo;
                Self(self.0.mul_reduce(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS))
            }
        }

        impl ::std::ops::MulAssign<Self> for #name {
            #[inline]
            fn mul_assign(&mut self, rhs: Self) {
                use algebra::modulo_traits::MulModuloAssign;
                self.0.mul_reduce_assign(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS)
            }
        }

        impl ::std::ops::MulAssign<&Self> for #name {
            #[inline]
            fn mul_assign(&mut self, rhs: &Self) {
                use algebra::modulo_traits::MulModuloAssign;
                self.0.mul_reduce_assign(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS)
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
                use algebra::modulo_traits::NegModulo;
                Self(self.0.neg_reduce(#modulus))
            }
        }
    }
}

pub(crate) fn pow_reduce_ops(name: &Ident, field_ty: &Type) -> TokenStream {
    quote! {
        impl num_traits::Pow<<Self as algebra::ring::Ring>::Order> for #name {
            type Output = Self;

            #[inline]
            fn pow(self, rhs: <Self as algebra::ring::Ring>::Order) -> Self::Output {
                use algebra::modulo_traits::PowModulo;
                Self(self.0.pow_reduce(rhs, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS))
            }
        }
    }
}

pub(crate) fn div_reduce_ops(name: &Ident, field_ty: &Type) -> TokenStream {
    quote! {
        impl ::std::ops::Div<Self> for #name {
            type Output = Self;

            #[inline]
            fn div(self, rhs: Self) -> Self::Output {
                use algebra::modulo_traits::DivModulo;
                Self(self.0.div_reduce(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS))
            }
        }

        impl ::std::ops::Div<&Self> for #name {
            type Output = Self;

            #[inline]
            fn div(self, rhs: &Self) -> Self::Output {
                use algebra::modulo_traits::DivModulo;
                Self(self.0.div_reduce(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS))
            }
        }

        impl ::std::ops::DivAssign<Self> for #name {
            #[inline]
            fn div_assign(&mut self, rhs: Self) {
                use algebra::modulo_traits::DivModuloAssign;
                self.0.div_reduce_assign(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS)
            }
        }

        impl ::std::ops::DivAssign<&Self> for #name {
            #[inline]
            fn div_assign(&mut self, rhs: &Self) {
                use algebra::modulo_traits::DivModuloAssign;
                self.0.div_reduce_assign(rhs.0, &<Self as algebra::field::BarrettConfig<#field_ty>>::BARRETT_MODULUS)
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
                use algebra::modulo_traits::InvModulo;
                Self(self.0.inv_reduce(#modulus))
            }
        }
    }
}
