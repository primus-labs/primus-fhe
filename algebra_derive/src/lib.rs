mod ast;
mod attr;
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
