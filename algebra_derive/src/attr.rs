use quote::ToTokens;
use syn::{DeriveInput, Error, Expr, Lit, LitInt, Meta, Type};

pub(crate) struct Attrs {
    pub(crate) modulus_type: ModulusType,
    pub(crate) modulus_value: ModulusValue,
}

#[derive(Clone, Copy)]
pub(crate) enum ModulusValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

#[derive(Clone, Copy, Default)]
pub(crate) enum ModulusType {
    #[default]
    Barrett,
}

impl ModulusValue {
    pub(crate) fn into_token_stream(self) -> proc_macro2::TokenStream {
        match self {
            ModulusValue::U8(m) => m.into_token_stream(),
            ModulusValue::U16(m) => m.into_token_stream(),
            ModulusValue::U32(m) => m.into_token_stream(),
            ModulusValue::U64(m) => m.into_token_stream(),
        }
    }

    pub(crate) fn check_leading_zeros(self, field: &syn::Field) -> syn::Result<()> {
        let (leading_zeros, name) = match self {
            ModulusValue::U8(m) => (m.leading_zeros(), "u8"),
            ModulusValue::U16(m) => (m.leading_zeros(), "u16"),
            ModulusValue::U32(m) => (m.leading_zeros(), "u32"),
            ModulusValue::U64(m) => (m.leading_zeros(), "u64"),
        };
        if leading_zeros < 2 {
            return Err(Error::new_spanned(
                field,
                format!(
                    "Modulus is too big! It should be smaller than `{}::MAX >> 2`",
                    name
                ),
            ));
        }
        Ok(())
    }
}

pub(crate) fn get(node: &DeriveInput, field: crate::ast::Field) -> syn::Result<Attrs> {
    let modulus_type = ModulusType::Barrett;

    for attr in node.attrs.iter() {
        if attr.path().is_ident("modulus") {
            if let Meta::NameValue(meta) = &attr.meta {
                if let Expr::Lit(expr) = &meta.value {
                    if let Lit::Int(lit_str) = &expr.lit {
                        return parse_modulus_value(lit_str, modulus_type, field);
                    }
                }
            }
        }
    }

    Err(Error::new_spanned(node, "modulus should supplied"))
}

fn parse_modulus_value(
    modulus: &LitInt,
    modulus_type: ModulusType,
    field: crate::ast::Field,
) -> syn::Result<Attrs> {
    if let Type::Path(type_path) = field.ty {
        match type_path.to_token_stream().to_string().as_str() {
            "u8" => {
                let modulus_value: u8 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        field.original,
                        "It's not possible to parse modulus into u8 type.",
                    )
                })?;
                return Ok(Attrs {
                    modulus_value: ModulusValue::U8(modulus_value),
                    modulus_type,
                });
            }
            "u16" => {
                let modulus_value: u16 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        field.original,
                        "It's not possible to parse modulus into u16 type.",
                    )
                })?;
                return Ok(Attrs {
                    modulus_value: ModulusValue::U16(modulus_value),
                    modulus_type,
                });
            }
            "u32" => {
                let modulus_value: u32 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        field.original,
                        "It's not possible to parse modulus into u32 type.",
                    )
                })?;
                return Ok(Attrs {
                    modulus_value: ModulusValue::U32(modulus_value),
                    modulus_type,
                });
            }
            "u64" => {
                let modulus_value: u64 = modulus.base10_digits().parse().map_err(|_| {
                    Error::new_spanned(
                        field.original,
                        "It's not possible to parse modulus into u64 type.",
                    )
                })?;
                return Ok(Attrs {
                    modulus_value: ModulusValue::U64(modulus_value),
                    modulus_type,
                });
            }
            _ => {
                return Err(Error::new_spanned(
                    field.original,
                    "The type supplied is unsupported.",
                ));
            }
        }
    }
    Err(Error::new_spanned(
        field.original,
        "Unable to check the inner type.",
    ))
}
