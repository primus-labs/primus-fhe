use syn::{Attribute, Expr, Lit, LitInt, Meta, Result};

pub(crate) struct Attrs {
    pub(crate) modulus: Option<LitInt>,
}

pub(crate) fn get(input: &[Attribute]) -> Result<Attrs> {
    let mut attrs = Attrs { modulus: None };

    for attr in input {
        if attr.path().is_ident("modulus") {
            if let Meta::NameValue(meta) = &attr.meta {
                if let Expr::Lit(expr) = &meta.value {
                    if let Lit::Int(lit_str) = &expr.lit {
                        attrs.modulus = Some(lit_str.clone());
                    }
                }
            }
        }
    }

    Ok(attrs)
}
