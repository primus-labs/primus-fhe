use quote::ToTokens;

#[derive(Clone, Copy)]
pub(crate) enum Modulus {
    U16(u16),
    U32(u32),
    U64(u64),
}

impl Modulus {
    /// Parses the bare word type and checks the literal before computing a reciprocal.
    pub(crate) fn from_syn(value: &syn::LitInt, ty: &syn::Path) -> syn::Result<Self> {
        let ty = ty.get_ident().ok_or_else(|| {
            syn::Error::new_spanned(
                ty,
                "The type for modulus is invalid. It can only be u16, u32 or u64.",
            )
        })?;
        let modulus = match ty.to_string().as_str() {
            "u16" => Self::U16(value.base10_parse()?),
            "u32" => Self::U32(value.base10_parse()?),
            "u64" => Self::U64(value.base10_parse()?),
            _ => {
                return Err(syn::Error::new_spanned(
                    ty,
                    "The type for modulus is invalid. It can only be u16, u32 or u64.",
                ));
            }
        };
        modulus.validate_range(value)?;
        Ok(modulus)
    }

    /// Reserve two high bits for lazy Barrett residues and intermediate corrections.
    fn validate_range(self, literal: &syn::LitInt) -> syn::Result<()> {
        let (value, bits) = match self {
            Self::U16(value) => (u64::from(value), u16::BITS),
            Self::U32(value) => (u64::from(value), u32::BITS),
            Self::U64(value) => (value, u64::BITS),
        };
        if value <= 1 {
            return Err(syn::Error::new_spanned(
                literal,
                "The modulus must be greater than 1.",
            ));
        }

        if value >= 1u64 << (bits - 2) {
            return Err(syn::Error::new_spanned(
                literal,
                "The modulus must be less than 2^(BITS - 2).",
            ));
        }
        Ok(())
    }

    /// Emits both reciprocal limbs as literals of the selected word type.
    pub(crate) fn reciprocal_tokens(self) -> [proc_macro2::TokenStream; 2] {
        match self {
            Self::U16(value) => reciprocal_limbs(value.into(), u16::BITS)
                .map(|limb| (limb as u16).to_token_stream()),
            Self::U32(value) => reciprocal_limbs(value.into(), u32::BITS)
                .map(|limb| (limb as u32).to_token_stream()),
            Self::U64(value) => reciprocal_limbs(value.into(), u64::BITS)
                .map(|limb| (limb as u64).to_token_stream()),
        }
    }

    pub(crate) fn into_token_stream(self) -> proc_macro2::TokenStream {
        match self {
            Modulus::U16(v) => v.to_token_stream(),
            Modulus::U32(v) => v.to_token_stream(),
            Modulus::U64(v) => v.to_token_stream(),
        }
    }
}

/// Computes the two limbs of `floor(B² / q)` by dividing one base-B digit at a time.
/// The first remainder is below q, so shifting it fits in u128 even when B² does not.
fn reciprocal_limbs(modulus: u128, word_bits: u32) -> [u128; 2] {
    let radix = 1u128 << word_bits;
    let high = radix / modulus;
    let low = ((radix % modulus) << word_bits) / modulus;
    [low, high]
}
