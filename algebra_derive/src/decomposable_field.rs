use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

use crate::ast::Input;

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_decomposable_field(input))
}

fn impl_decomposable_field(input: Input) -> TokenStream {
    let name = &input.ident;

    quote! {
        impl ::algebra::DecomposableField for #name{
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
