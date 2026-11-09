use quote::ToTokens;

#[derive(Clone, Copy)]
pub(crate) enum Modulus {
    U16(u16),
    U32(u32),
    U64(u64),
}

impl Modulus {
    /// Parse the supported bare word type and reject literals that overflow it.
    pub(crate) fn from_syn(value: &syn::LitInt, ty: &syn::Path) -> syn::Result<Self> {
        let ty = ty.get_ident().ok_or_else(|| {
            syn::Error::new_spanned(
                ty,
                "The type for modulus is invalid. It can only be u16, u32 or u64.",
            )
        })?;
        match ty.to_string().as_str() {
            "u16" => {
                let value = value.base10_parse::<u16>()?;
                Ok(Self::U16(value))
            }
            "u32" => {
                let value = value.base10_parse::<u32>()?;
                Ok(Self::U32(value))
            }
            "u64" => {
                let value = value.base10_parse::<u64>()?;
                Ok(Self::U64(value))
            }
            _ => Err(syn::Error::new_spanned(
                ty,
                "The type for modulus is invalid. It can only be u16, u32 or u64.",
            )),
        }
    }

    /// Reserve two high bits for lazy Barrett residues and intermediate corrections.
    pub(crate) fn validate_range(&self, value: &syn::LitInt) -> syn::Result<()> {
        let is_too_small = match self {
            Modulus::U16(value) => *value <= 1,
            Modulus::U32(value) => *value <= 1,
            Modulus::U64(value) => *value <= 1,
        };
        if is_too_small {
            return Err(syn::Error::new_spanned(
                value,
                "The modulus must be greater than 1.",
            ));
        }

        let n = match self {
            Modulus::U16(v) => v.leading_zeros(),
            Modulus::U32(v) => v.leading_zeros(),
            Modulus::U64(v) => v.leading_zeros(),
        };
        if n < 2 {
            return Err(syn::Error::new_spanned(
                value,
                "The modulus must be less than 2^(BITS - 2).",
            ));
        }
        Ok(())
    }

    pub(crate) fn into_token_stream(self) -> proc_macro2::TokenStream {
        match self {
            Modulus::U16(v) => v.to_token_stream(),
            Modulus::U32(v) => v.to_token_stream(),
            Modulus::U64(v) => v.to_token_stream(),
        }
    }
}
