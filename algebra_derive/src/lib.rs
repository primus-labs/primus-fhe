mod ast;
mod attr;
mod basic;
mod field;
mod ntt;
mod ops;
mod prime;
mod random;
mod ring;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(Ring, attributes(backend, modulus))]
pub fn derive_ring(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    ring::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(Field, attributes(backend, modulus))]
pub fn derive_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    field::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(AlgebraRandom, attributes(backend, modulus))]
pub fn derive_random(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    random::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(Prime, attributes(backend, modulus))]
pub fn derive_prime(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    prime::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(NTTField, attributes(backend, modulus))]
pub fn derive_ntt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    ntt::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
