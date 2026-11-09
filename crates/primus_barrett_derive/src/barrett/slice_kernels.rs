use proc_macro2::TokenStream;
use quote::quote;

/// Chooses the forwarding module during expansion, keeping generated signatures
/// and attributes identical across scalar and portable-SIMD implementations.
pub(super) fn kernel_module() -> TokenStream {
    if cfg!(feature = "simd") {
        quote!(::primus_modulus::common::compact::simd)
    } else {
        quote!(::primus_modulus::common::compact::slice)
    }
}

/// Portable-SIMD multiplication needs an explicit vector modulus type; scalar
/// multiplication infers its parameters from the generated zero-sized context.
pub(super) fn multiplication_generics(ty: &syn::Path) -> TokenStream {
    if cfg!(feature = "simd") {
        quote!(::<#ty, Self, ::primus_modulus::SimdBarrettModulus<#ty>>)
    } else {
        TokenStream::new()
    }
}
