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

fn binary(name: &Ident, binary_name: &Ident, field_ty: &syn::Type) -> TokenStream {
    quote! {
        #[doc = concat!("The binary distribution for [`", stringify!(#name), "`].")]
        ///
        /// prob\[1] = prob\[0] = 0.5
        #[derive(Clone, Copy, Debug)]
        pub struct #binary_name;

        impl ::rand::distributions::Distribution<#name> for #binary_name {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                #name((rng.next_u32() & 0b1) as #field_ty)
            }
        }
    }
}

fn ternary(name: &Ident, ternary_name: &Ident, modulus: &syn::LitInt) -> TokenStream {
    quote! {
        #[doc = concat!("The ternary distribution for [`", stringify!(#name), "`].")]
        ///
        /// prob\[1] = prob\[-1] = 0.25
        ///
        /// prob\[0] = 0.5
        #[derive(Clone, Copy, Debug)]
        pub struct #ternary_name;

        impl ::rand::distributions::Distribution<#name> for #ternary_name {
            #[inline]
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                unsafe {*[#name(0), #name(0), #name(1), #name(#modulus - 1)].get_unchecked((rng.next_u32() & 0b11) as usize)}
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

fn normal(
    name: &Ident,
    sample_name: &Ident,
    field_ty: &syn::Type,
    modulus: &syn::LitInt,
) -> TokenStream {
    quote! {
        #[doc = concat!("The normal distribution `N(mean, std_dev**2)` for [`", stringify!(#name), "`].")]
        #[derive(Clone, Copy, Debug)]
        pub struct #sample_name {
            inner: ::rand_distr::Normal<f64>,
            std_dev_max: f64,
        }

        impl #sample_name {
            /// Construct, from mean and standard deviation
            ///
            /// Parameters:
            ///
            /// -   mean (`μ`, unrestricted)
            /// -   standard deviation (`σ`, must be finite)
            #[inline]
            pub fn new(mean: f64, std_dev: f64) -> Result<#sample_name, ::algebra::AlgebraError> {
                match ::rand_distr::Normal::new(mean, std_dev) {
                    Ok(inner) => {
                        let std_dev_max = std_dev * 6.0;
                        Ok(#sample_name { inner, std_dev_max })
                    },
                    Err(_) => Err(::algebra::AlgebraError::DistributionError),
                }
            }

            /// Returns `6σ` of the distribution.
            #[inline]
            pub fn std_dev_max(&self) -> f64 {
                self.std_dev_max
            }
        }

        impl ::algebra::NormalInfo for #sample_name {
            /// Returns the mean (`μ`) of the distribution.
            #[inline]
            fn mean(&self) -> f64 {
                self.inner.mean()
            }

            /// Returns the standard deviation (`σ`) of the distribution.
            #[inline]
            fn std_dev(&self) -> f64 {
                self.inner.std_dev()
            }
        }

        impl ::rand::distributions::Distribution<#name> for #sample_name {
            fn sample<R: ::rand::Rng + ?Sized>(&self, rng: &mut R) -> #name {
                let mean = self.inner.mean();
                loop {
                    let value = self.inner.sample(rng);
                    if (value - mean).abs() < self.std_dev_max {
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
    let binary_name = format_ident!("Binary{}", name);
    let ternary_name = format_ident!("Ternary{}", name);
    let normal_name = format_ident!("Normal{}", name);

    let impl_standard = standard(name, &standard_name);
    let impl_binary = binary(name, &binary_name, field_ty);
    let impl_ternary = ternary(name, &ternary_name, &modulus);
    let impl_uniform = uniform(name, field_ty, &modulus);
    let impl_normal = normal(name, &normal_name, field_ty, &modulus);

    quote! {
        #impl_standard

        #impl_binary

        #impl_ternary

        #impl_uniform

        #impl_normal

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

            type BinaryDistribution = #binary_name;

            type TernaryDistribution = #ternary_name;

            type NormalDistribution = #normal_name;

            #[inline]
            fn standard_distribution() -> Self::StandardDistribution {
                #standard_name.clone()
            }

            #[inline]
            fn binary_distribution() -> Self::BinaryDistribution {
                #binary_name
            }

            #[inline]
            fn ternary_distribution() -> Self::TernaryDistribution {
                #ternary_name
            }

            #[inline]
            fn normal_distribution(
                mean: f64,
                std_dev: f64,
            ) -> Result<Self::NormalDistribution, ::algebra::AlgebraError> {
                #normal_name::new(mean, std_dev)
            }
        }
    }
}
