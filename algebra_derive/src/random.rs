use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::{DeriveInput, Result};

use crate::{ast::Input, attr::ModulusValue};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_random(input))
}

fn uniform(
    name: &Ident,
    uniform_name: &Ident,
    field_ty: &syn::Type,
    sample_type: &TokenStream,
) -> TokenStream {
    quote! {
        static #uniform_name: ::once_cell::sync::Lazy<::algebra::FieldUniformSampler<#name>> =
            ::once_cell::sync::Lazy::new(|| <#name as ::algebra::Random>::uniform_sampler());

        impl ::rand::distributions::Distribution<#name> for ::rand::distributions::Standard {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                #uniform_name.sample(rng)
            }
        }

        impl ::rand::distributions::Distribution<#name> for ::algebra::FieldUniformSampler<#name> {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                use ::algebra::Widening;
                let range = self.range as #sample_type;
                let thresh = self.thresh as #sample_type;
                let hi = loop {
                    let (lo, hi) = rng.gen::<#sample_type>().widen_mul(range);
                    if lo >= thresh {
                        break hi;
                    }
                };
                #name(self.low.wrapping_add(hi as #field_ty))
            }
        }
    }
}

fn binary(name: &Ident, field_ty: &syn::Type) -> TokenStream {
    quote! {
        impl ::rand::distributions::Distribution<#name> for ::algebra::FieldBinarySampler {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                #name((rng.next_u32() & 0b1) as #field_ty)
            }
        }
    }
}

fn ternary(name: &Ident, modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::rand::distributions::Distribution<#name> for ::algebra::FieldTernarySampler {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                [#name(0), #name(0), #name(1), #name(#modulus - 1)][(rng.next_u32() & 0b11) as usize]
            }
        }
    }
}

fn gaussian(name: &Ident, field_ty: &syn::Type, modulus: &TokenStream) -> TokenStream {
    quote! {
        impl ::rand::distributions::Distribution<#name> for ::algebra::FieldDiscreteGaussianSampler {
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                let mean = self.mean();
                let gaussian = self.gaussian();
                loop {
                    let value = gaussian.sample(rng);
                    if (value - mean).abs() < self.max_std_dev() {
                        let round = value.round();
                        if round < 0. {
                            return #name((#modulus as f64 + value) as #field_ty);
                        } else {
                            return #name(value as #field_ty);
                        }
                    }
                }
            }
        }
    }
}

fn impl_random(input: Input) -> TokenStream {
    let name = &input.ident;
    let modulus_value = input.attrs.modulus_value;
    let modulus = modulus_value.into_token_stream();
    let field_ty = input.field.ty;

    let uniform_name = format_ident!("UNIFORM_{}", name.to_string().to_uppercase());

    let sample_type = match modulus_value {
        ModulusValue::U8(_) | ModulusValue::U16(_) | ModulusValue::U32(_) => quote!(u32),
        ModulusValue::U64(_) => quote!(u64),
    };

    let impl_uniform = uniform(name, &uniform_name, field_ty, &sample_type);
    let impl_binary = binary(name, field_ty);
    let impl_ternary = ternary(name, &modulus);
    let impl_gaussian = gaussian(name, field_ty, &modulus);

    quote! {
        #impl_uniform

        #impl_binary

        #impl_ternary

        #impl_gaussian

        impl #name {
            #[doc = concat!("Get a random value of [`", stringify!(#name), "`].")]
            #[inline]
            pub fn random<R>(rng: &mut R) -> Self
            where
                R: ::rand::Rng + ::rand::CryptoRng,
            {
                use ::rand::distributions::Distribution;
                #uniform_name.sample(rng)
            }
        }

        impl ::algebra::Random for #name {
            type UniformSampler = ::algebra::FieldUniformSampler<#name>;

            #[inline]
            fn uniform_sampler() -> ::algebra::FieldUniformSampler<#name> {
                ::algebra::FieldUniformSampler {
                    low: 0,
                    range: #modulus,
                    thresh: {
                        let range = #modulus as #sample_type;
                        (range.wrapping_neg() % range) as #field_ty
                    },
                }
            }

            #[inline(always)]
            fn binary_sampler() -> ::algebra::FieldBinarySampler {
                ::algebra::FieldBinarySampler
            }

            #[inline(always)]
            fn ternary_sampler() -> ::algebra::FieldTernarySampler {
                ::algebra::FieldTernarySampler
            }

            #[inline]
            fn gaussian_sampler(
                mean: f64,
                std_dev: f64,
            ) -> Result<::algebra::FieldDiscreteGaussianSampler, ::algebra::AlgebraError> {
                ::algebra::FieldDiscreteGaussianSampler::new(mean, std_dev)
            }

            #[inline]
            fn gaussian_sampler_with_max_limit(
                mean: f64,
                std_dev: f64,
                max_std_dev: f64,
            ) -> Result<::algebra::FieldDiscreteGaussianSampler, ::algebra::AlgebraError> {
                ::algebra::FieldDiscreteGaussianSampler::new_with_max(mean, std_dev, max_std_dev)
            }
        }
    }
}
