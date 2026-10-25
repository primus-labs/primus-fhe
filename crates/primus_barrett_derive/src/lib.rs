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

/// Derives a zero-sized Barrett modulus context for a compile-time constant.
///
/// The input must be a unit struct. The `modulus` attribute accepts a bare
/// unsigned integer type (`u16`, `u32`, or `u64`) and a modulus satisfying
/// `1 < value < 2^(BITS - 2)`. Invalid inputs produce a compile-time error.
///
/// Generated paths start with `::primus_modulus`. The consuming crate must make
/// that dependency available under its original name, normally by enabling its
/// `derive` feature. A renamed dependency needs a crate-root alias named
/// `primus_modulus`; depending only on this procedural-macro crate is insufficient.
///
/// The macro generates associated `value()` and `ratio()` functions together
/// with the scalar, slice, lazy-reduction, inverse, and dot-product traits used
/// by `primus_modulus`. It also implements `Copy`, `Clone`, `PartialEq`, `Eq`,
/// `Debug`, and `Hash`; do not derive those traits separately. Canonical slice
/// multiply-add selects shared native kernels on supported x86_64 CPUs, even
/// without the `simd` feature: non-power-of-two `u32`, or non-power-of-two `u64`
/// below `2^50` with IFMA support, for slices of at least 32 elements. Other cases
/// retain constant-modulus fallbacks. The `simd` feature enables portable-SIMD
/// fallbacks and SIMD implementations for the other slice operations.
///
/// # Example
///
/// ```ignore
/// use primus_modulus::Barrett;
///
/// #[derive(Barrett)]
/// #[modulus(ty = u32, value = 536813569)]
/// struct Modulus;
///
/// assert_eq!(Modulus::value(), 536_813_569);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the actual parsing/validation pipeline without invoking rustc for each bad input.
    /// Successful expansions are compiled and checked in primus_modulus/tests/derives.rs.
    #[test]
    fn rejects_invalid_shape_type_and_modulus() {
        let cases = [
            (
                "#[modulus(ty = u32, value = 97)] struct M(u32);",
                "Expected no fields",
            ),
            (
                "#[modulus(ty = i32, value = 97)] struct M;",
                "type for modulus is invalid",
            ),
            (
                "#[modulus(ty = core::primitive::u32, value = 97)] struct M;",
                "type for modulus is invalid",
            ),
            ("#[modulus(ty = u16, value = 65536)] struct M;", "too large"),
            (
                "#[modulus(ty = u32, value = 0)] struct M;",
                "greater than 1",
            ),
            (
                "#[modulus(ty = u64, value = 1)] struct M;",
                "greater than 1",
            ),
            (
                "#[modulus(ty = u16, value = 16384)] struct M;",
                "less than 2^(BITS - 2)",
            ),
            (
                "#[modulus(ty = u32, value = 1073741824)] struct M;",
                "less than 2^(BITS - 2)",
            ),
            (
                "#[modulus(ty = u64, value = 4611686018427387904)] struct M;",
                "less than 2^(BITS - 2)",
            ),
        ];
        for (source, expected) in cases {
            let input = syn::parse_str::<DeriveInput>(source).unwrap();
            let error = match BarrettModulusInput::from_derive_input(&input) {
                Err(error) => error.to_string(),
                Ok(parsed) => barrett::derive(&parsed).unwrap_err().to_string(),
            };
            assert!(error.contains(expected), "{source}: {error}");
        }
    }
}
