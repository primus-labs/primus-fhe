use darling::FromDeriveInput;
use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

mod barrett;
mod modulus;

pub(crate) use modulus::Modulus;

#[derive(Debug, FromDeriveInput)]
#[darling(attributes(modulus), supports(struct_unit))]
struct BarrettModulusInput {
    vis: syn::Visibility,
    ident: syn::Ident,
    ty: syn::Path,
    value: syn::LitInt,
}

/// Derive the Barrett Modulus for the const modulus value.
///
/// ## Examples
///
/// ```ignore
/// #[derive(Barrett)]
/// #[modulus(ty = u32, value = 536813569)]
/// struct Modulus;
/// ```
#[proc_macro_derive(Barrett, attributes(modulus))]
pub fn derive_barrett(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let parsed = match BarrettModulusInput::from_derive_input(&input) {
        Ok(v) => v,
        Err(e) => return e.write_errors().into(),
    };

    barrett::derive(&parsed)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
