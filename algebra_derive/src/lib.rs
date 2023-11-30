//! Define some derive macro for `algebra` crate.
//! 
//! You use these to define some ring, field, prime field, ntt field and the random function for them.

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

/// Derive macro generating an impl of the trait `algebra::ring::Ring`.
///
/// This also generating some compitation for it, e.g. `Add`, `Sub`, `Mul`, `Neg` and `Pow`.
///
/// By the way, it also generating impl of the trait `Zero`, `One`, `Display`.
///
/// But it will note generating impl of the trait `Clone`, `Copy`, `Debug`, `Default`, `Eq`, `PartialEq`, `PartialOrd`, `Ord`.
/// You need to make it by yourself.
/// 
/// It can used for unnamed struct with only one element in `u8`, `u16`, `u32`, `u64`.
/// 
/// # Example
/// 
/// ```ignore
/// #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Random)]
/// #[modulus = 512]
/// pub struct R512(u32);
/// ```
#[proc_macro_derive(Ring, attributes(modulus))]
pub fn derive_ring(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    ring::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Derive macro generating an impl of the trait `algebra::field::Field`.
///
/// This also generating some compitation for it, e.g. `Div` and `Inv`.
/// 
/// It can used for unnamed struct with only one element in `u8`, `u16`, `u32`, `u64`.
/// 
/// # Example
/// 
/// ```ignore
/// #[derive(
///     Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
/// )]
/// #[modulus = 132120577]
/// pub struct Fp32(u32);
/// ```
/// 
/// It's based the Derive macro `Ring`.
#[proc_macro_derive(Field, attributes(modulus))]
pub fn derive_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    field::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Derive macro generating an impl of the trait `algebra::field::FieldDistribution`.
///
/// Then you can use `rand` crate to generate it randomly.
///
/// Besides the `Standard` and `Uniform` Distribution, you can also use the binary distribution,
/// ternary distribution and normal distribution.
#[proc_macro_derive(Random, attributes(modulus))]
pub fn derive_random(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    random::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Derive macro generating an impl of the trait `algebra::field::PrimeField`.
/// 
/// It's based the Derive macro `Field`.
#[proc_macro_derive(Prime, attributes(modulus))]
pub fn derive_prime(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    prime::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Derive macro generating an impl of the trait `algebra::field::NTTField`.
/// 
/// It's based the Derive macro `Prime`.
#[proc_macro_derive(NTT, attributes(modulus))]
pub fn derive_ntt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    ntt::derive(&input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}
