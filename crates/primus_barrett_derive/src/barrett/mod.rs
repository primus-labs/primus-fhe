use proc_macro2::TokenStream;
use syn::Result;

use crate::{BarrettModulusInput, Modulus};

mod basic;

mod lazy_ops;
mod lazy_slice_ops;
mod ops;
mod slice_kernels;
mod slice_ops;

/// Validate the type and reciprocal range before computing constants or emitting arithmetic.
#[inline]
pub(super) fn derive(input: &BarrettModulusInput) -> Result<TokenStream> {
    let modulus = Modulus::from_syn(&input.value, &input.ty)?;
    Ok(impl_barrett(input, modulus))
}

/// Assemble implementations around one precomputed reciprocal; modulus has already been validated.
fn impl_barrett(input: &BarrettModulusInput, modulus: Modulus) -> TokenStream {
    let vis = &input.vis;

    let name = &input.ident;

    let ty = &input.ty;

    let ratio = modulus.reciprocal_tokens();
    let modulus = modulus.into_token_stream();

    let impl_basic = basic::basic(vis, name, &modulus, ty, &ratio);

    let impl_simd = basic::into_simd_modulus(name, &modulus, ty, &ratio);

    let lazy_ops = lazy_ops::lazy_ops(name, &modulus, ty, &ratio);

    let ops = ops::ops(name, &modulus, ty);

    let lazy_slice_ops = lazy_slice_ops::lazy_slice_ops(name, &modulus, ty);

    let slice_ops = slice_ops::slice_ops(name, &modulus, ty);

    let slice_inv_ops = slice_ops::slice_inv_ops(name, ty);

    quote::quote! {
        #impl_basic

        #impl_simd

        #lazy_ops

        #ops

        #lazy_slice_ops

        #slice_ops

        #slice_inv_ops
    }
}
