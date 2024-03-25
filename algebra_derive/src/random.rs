use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use syn::{DeriveInput, Result};

use crate::ast::Input;

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_random(input))
}

fn standard(name: &Ident, standard_name: &Ident) -> TokenStream {
    quote! {
        static #standard_name: ::once_cell::sync::Lazy<::rand::distributions::Uniform<#name>> =
            ::once_cell::sync::Lazy::new(|| ::rand::distributions::Uniform::new_inclusive(#name(0), #name::max()));

        impl ::rand::distributions::Distribution<#name> for ::rand::distributions::Standard {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                #standard_name.sample(rng)
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

fn ternary(name: &Ident, modulus: &syn::LitInt) -> TokenStream {
    quote! {
        impl ::rand::distributions::Distribution<#name> for ::algebra::FieldTernarySampler {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                [#name(0), #name(0), #name(1), #name(#modulus - 1)][(rng.next_u32() & 0b11) as usize]
            }
        }
    }
}

fn uniform(name: &Ident, field_ty: &syn::Type, modulus: &syn::LitInt) -> TokenStream {
    let sample_name = format_ident!("Uniform{}", name);
    quote! {
        #[derive(Clone, Copy, Debug)]
        pub struct #sample_name(::rand::distributions::uniform::UniformInt<#field_ty>);

        impl ::rand::distributions::uniform::UniformSampler for #sample_name {
            type X = #name;

            #[inline]
            fn new<B1, B2>(low: B1, high: B2) -> Self
            where
                B1: ::rand::distributions::uniform::SampleBorrow<Self::X> + Sized,
                B2: ::rand::distributions::uniform::SampleBorrow<Self::X> + Sized,
            {
                #sample_name(::rand::distributions::uniform::UniformInt::<#field_ty>::new_inclusive(
                    low.borrow().0,
                    high.borrow().0 - 1,
                ))
            }

            #[inline]
            fn new_inclusive<B1, B2>(low: B1, high: B2) -> Self
            where
                B1: ::rand::distributions::uniform::SampleBorrow<Self::X> + Sized,
                B2: ::rand::distributions::uniform::SampleBorrow<Self::X> + Sized,
            {
                let high = if high.borrow().0 >= #modulus - 1 {
                    #modulus - 1
                } else {
                    high.borrow().0
                };
                #sample_name(::rand::distributions::uniform::UniformInt::<#field_ty>::new_inclusive(low.borrow().0, high))
            }

            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> Self::X {
                #name(self.0.sample(rng))
            }
        }

        impl ::rand::distributions::uniform::SampleUniform for #name {
            type Sampler = #sample_name;
        }
    }
}

fn gaussian(name: &Ident, field_ty: &syn::Type, modulus: &syn::LitInt) -> TokenStream {
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
    let modulus = input.attrs.modulus.unwrap();
    let field_ty = input.field.ty;

    let standard_name = format_ident!("STANDARD_{}", name.to_string().to_uppercase());

    let impl_standard = standard(name, &standard_name);
    let impl_binary = binary(name, field_ty);
    let impl_ternary = ternary(name, &modulus);
    let impl_uniform = uniform(name, field_ty, &modulus);
    let impl_gaussian = gaussian(name, field_ty, &modulus);

    quote! {
        #impl_standard

        #impl_binary

        #impl_ternary

        #impl_uniform

        #impl_gaussian

        impl #name {
            #[doc = concat!("Get a random value of [`", stringify!(#name), "`].")]
            #[inline]
            pub fn random<R>(rng: &mut R) -> Self
            where
                R: ::rand::Rng + ::rand::CryptoRng,
            {
                use ::rand::distributions::Distribution;
                #standard_name.sample(rng)
            }
        }

        impl ::algebra::Random for #name {
            type StandardDistribution = ::rand::distributions::Uniform<#name>;

            #[inline]
            fn standard_distribution() -> Self::StandardDistribution {
                #standard_name.clone()
            }

            #[inline]
            fn binary_sampler() -> ::algebra::FieldBinarySampler {
                ::algebra::FieldBinarySampler
            }

            #[inline]
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
