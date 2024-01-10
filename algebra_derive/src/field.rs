use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::{ast::Input, ops::*};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_field_with_ops(input))
}

fn impl_field_with_ops(input: Input) -> TokenStream {
    let name = &input.ident;

    let modulus = input.attrs.modulus.unwrap();

    let impl_div = div_reduce_ops(name);

    let impl_inv = inv_reduce_ops(name, &modulus);

    let impl_field = impl_field(name);

    quote! {
        #impl_div

        #impl_inv

        #impl_field
    }
}

#[inline]
fn impl_field(name: &proc_macro2::Ident) -> TokenStream {
    quote! {
        impl algebra::Field for #name {
                #[inline]
                fn add_mul(self, a: Self, b: Self) -> Self {
                    use algebra::Widening;
                    use algebra::reduce::Reduce;
                    Self(a.0.carry_mul(b.0, self.0).reduce(&<Self as algebra::ModulusConfig>::MODULUS))
                }

                #[inline]
                fn mul_add(self, a: Self, b: Self) -> Self {
                    use algebra::Widening;
                    use algebra::reduce::Reduce;
                    Self(self.0.carry_mul(a.0, b.0).reduce(&<Self as algebra::ModulusConfig>::MODULUS))
                }

                #[inline]
                fn add_mul_assign(&mut self, a: Self, b: Self) {
                    use algebra::Widening;
                    use algebra::reduce::Reduce;
                    self.0 = a.0.carry_mul(b.0, self.0).reduce(&<Self as algebra::ModulusConfig>::MODULUS);
                }

                #[inline]
                fn mul_add_assign(&mut self, a: Self, b: Self) {
                    use algebra::Widening;
                    use algebra::reduce::Reduce;
                    self.0 = self.0.carry_mul(a.0, b.0).reduce(&<Self as algebra::ModulusConfig>::MODULUS);
                }
        }
    }
}
