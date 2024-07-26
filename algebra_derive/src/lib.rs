//! Define some derive macro for `algebra` crate.
//!
//! You use these to define some field, prime field, ntt field and the random functions for them.

mod ast;
mod attr;
mod basic;
mod decomposable_field;
mod fhe_field;
mod field;
mod ntt;
mod ops;
mod prime;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

/// Derive macro generates an impl of the trait `algebra::Field`.
///
/// This also generates some computation for it, e.g.
/// `Add`, `Sub`, `Mul`, `Neg`, `Pow`, `Div` and `Inv`.
///
/// By the way, it also generates impl of the trait `Zero`, `One`, `Display`.
///
/// And it will generate impl of the trait
/// `Clone`, `Copy`, `Debug`, `Default`, `Eq`, `PartialEq`, `PartialOrd`, `Ord`.
///
/// It can used for unnamed struct with only one element of `u8`, `u16`, `u32`, `u64`.
///
/// # Example
///
/// ```ignore
/// #[derive(Field, Random, Prime, NTT)]
/// #[modulus = 132120577]
/// pub struct Fp32(u32);
/// ```
#[proc_macro_derive(Field, attributes(modulus))]
pub fn derive_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    field::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Derive macro generating an impl of the trait `algebra::PrimeField`.
///
/// It's based the Derive macro `Field`.
///
/// # Example
///
/// ```ignore
/// #[derive(Field, Random, Prime, NTT)]
/// #[modulus = 132120577]
/// pub struct Fp32(u32);
/// ```
#[proc_macro_derive(Prime, attributes(modulus))]
pub fn derive_prime(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    prime::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(DecomposableField, attributes(modulus))]
pub fn derive_decomposable_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    decomposable_field::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[proc_macro_derive(FheField, attributes(modulus))]
pub fn derive_fhe_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    fhe_field::derive(&input)
        .unwrap_or_else(|err| err.into_compile_error())
        .into()
}

/// Derive macro generating an impl of the trait `algebra::NTTField`.
///
/// It's based the Derive macro `Prime`.
///
/// # Example
///
/// ```ignore
/// #[derive(Field, Random, Prime, NTT)]
/// #[modulus = 132120577]
/// pub struct Fp32(u32);
/// ```
#[proc_macro_derive(NTT, attributes(modulus))]
pub fn derive_ntt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    ntt::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
