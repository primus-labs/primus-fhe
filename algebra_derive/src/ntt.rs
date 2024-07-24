use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, Result};

use crate::{ast::Input, attr::ModulusValue};

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_ntt(input))
}

fn impl_ntt(input: Input) -> TokenStream {
    let name = &input.ident;
    let field_ty = input.field.ty;

    let modulus_value = input.attrs.modulus_value;
    let modulus = modulus_value.into_token_stream();

    #[cfg(feature = "concrete-ntt")]
    let table = match modulus_value {
        ModulusValue::U32(_) => quote! {::algebra::transformation::prime32::ConcreteTable<Self>},
        ModulusValue::U64(_) => quote! {::algebra::transformation::prime64::ConcreteTable<Self>},
        ModulusValue::U8(_) | ModulusValue::U16(_) => {
            quote! {::algebra::transformation::NTTTable<Self>}
        }
    };
    #[cfg(not(feature = "concrete-ntt"))]
    let table = quote! {::algebra::transformation::NTTTable<Self>};

    #[cfg(feature = "concrete-ntt")]
    let root = match modulus_value {
        ModulusValue::U32(_) | ModulusValue::U64(_) => quote! {Self},
        ModulusValue::U8(_) | ModulusValue::U16(_) => {
            quote! {::algebra::modulus::ShoupFactor<<Self as ::algebra::Field>::Value>}
        }
    };
    #[cfg(not(feature = "concrete-ntt"))]
    let root = quote! {::algebra::modulus::ShoupFactor<<Self as ::algebra::Field>::Value>};

    let ntt_table = format_ident!("NTT_TABLE{}", name.to_string().to_uppercase());
    let ntt_mutex = format_ident!("NTT_MUTEX{}", name.to_string().to_uppercase());

    let from_root = impl_from_root(modulus_value);
    let to_root = impl_to_root(modulus_value, &modulus);
    let mul_root = impl_mul_root(modulus_value, &modulus);
    let mul_root_assign = impl_mul_root_assign(modulus_value, &modulus);
    let generate_ntt_table = impl_generate_ntt_table(modulus_value, &table);

    quote! {
        static mut #ntt_table: ::once_cell::sync::OnceCell<::std::collections::HashMap<u32, ::std::sync::Arc<<#name as ::algebra::NTTField>::Table>>>
            = ::once_cell::sync::OnceCell::new();
        static #ntt_mutex: ::std::sync::Mutex<()> = ::std::sync::Mutex::new(());

        impl ::std::convert::From<usize> for #name {
            #[inline]
            fn from(value: usize) -> Self {
                let modulus = #modulus.try_into().unwrap();
                if value < modulus {
                    Self(value as #field_ty)
                } else {
                    Self((value % modulus) as #field_ty)
                }
            }
        }

        impl ::algebra::NTTField for #name {
            type Table = #table;

            type Root = #root;

            type Degree = #field_ty;

            #from_root

            #to_root

            #mul_root

            #mul_root_assign

            #[inline]
            fn is_primitive_root(root: Self, degree: Self::Degree) -> bool {
                debug_assert!(root.0 < #modulus);
                debug_assert!(
                    degree > 1 && degree.is_power_of_two(),
                    "degree must be a power of two and bigger than 1"
                );

                if root.0 == 0 {
                    return false;
                }

                ::num_traits::Pow::pow(root, degree >> 1).0 == #modulus - 1
            }

            fn try_primitive_root(degree: Self::Degree) -> Result<Self, ::algebra::AlgebraError> {
                // p-1
                let modulus_sub_one = #modulus - 1;

                // (p-1)/n
                let quotient = modulus_sub_one / degree;

                // (p-1) must be divisible by n
                if modulus_sub_one != quotient * degree {
                    return Err(::algebra::AlgebraError::NoPrimitiveRoot {
                        degree: degree.to_string(),
                        modulus: #modulus.to_string(),
                    });
                }

                let mut rng = ::rand::thread_rng();
                let distr = ::rand::distributions::Uniform::new_inclusive(2, #modulus - 1);

                let mut w = Self(0);

                if (0..100).any(|_| {
                    w = ::num_traits::Pow::pow(Self(::rand::Rng::sample(&mut rng, distr)), quotient);
                    Self::is_primitive_root(w, degree)
                }) {
                    Ok(w)
                } else {
                    Err(::algebra::AlgebraError::NoPrimitiveRoot {
                        degree: degree.to_string(),
                        modulus: #modulus.to_string(),
                    })
                }
            }

            fn try_minimal_primitive_root(degree: Self::Degree) -> Result<Self, ::algebra::AlgebraError> {
                let mut root = Self::try_primitive_root(degree)?;

                let generator_sq = (root * root).to_root();
                let mut current_generator = root;

                for _ in 0..degree {
                    if current_generator < root {
                        root = current_generator;
                    }

                    current_generator.mul_root_assign(generator_sq);
                }

                Ok(root)
            }

            #generate_ntt_table

            fn get_ntt_table(log_n: u32) -> Result<::std::sync::Arc<Self::Table>, ::algebra::AlgebraError> {
                if let Some(tables) = unsafe { #ntt_table.get() } {
                    if let Some(t) = tables.get(&log_n) {
                        return Ok(::std::sync::Arc::clone(t));
                    }
                }

                Self::init_ntt_table(&[log_n])?;
                Ok(::std::sync::Arc::clone(unsafe {
                    #ntt_table.get().unwrap().get(&log_n).unwrap()
                }))
            }

            fn init_ntt_table(log_ns: &[u32]) -> Result<(), ::algebra::AlgebraError> {
                let _g = #ntt_mutex.lock().unwrap();
                match unsafe { #ntt_table.get_mut() } {
                    Some(tables) => {
                        let new_log_ns: ::std::collections::HashSet<u32> = log_ns.iter().copied().collect();
                        let old_log_ns: ::std::collections::HashSet<u32> = tables.keys().copied().collect();
                        let difference = new_log_ns.difference(&old_log_ns);

                        for &log_n in difference {
                            let temp_table = Self::generate_ntt_table(log_n)?;
                            tables.insert(log_n, ::std::sync::Arc::new(temp_table));
                        }

                        Ok(())
                    }
                    None => {
                        let log_ns: ::std::collections::HashSet<u32> = log_ns.iter().copied().collect();
                        let mut map = ::std::collections::HashMap::with_capacity(log_ns.len());

                        for log_n in log_ns {
                            let temp_table = Self::generate_ntt_table(log_n)?;
                            map.insert(log_n, ::std::sync::Arc::new(temp_table));
                        }

                        if unsafe { #ntt_table.set(map).is_err() } {
                            Err(::algebra::AlgebraError::NTTTableError)
                        } else {
                            Ok(())
                        }
                    }
                }
            }
        }
    }
}

#[allow(unused_variables)]
fn impl_from_root(modulus_value: ModulusValue) -> TokenStream {
    #[cfg(feature = "concrete-ntt")]
    match modulus_value {
        ModulusValue::U32(_) | ModulusValue::U64(_) => {
            quote! {
                #[inline]
                fn from_root(root: Self::Root) -> Self {
                    root
                }
            }
        }
        ModulusValue::U8(_) | ModulusValue::U16(_) => {
            quote! {
                #[inline]
                fn from_root(root: Self::Root) -> Self {
                    Self(root.value())
                }
            }
        }
    }

    #[cfg(not(feature = "concrete-ntt"))]
    quote! {
        #[inline]
        fn from_root(root: Self::Root) -> Self {
            Self(root.value())
        }
    }
}

#[allow(unused_variables)]
fn impl_to_root(modulus_value: ModulusValue, modulus: &TokenStream) -> TokenStream {
    #[cfg(feature = "concrete-ntt")]
    match modulus_value {
        ModulusValue::U32(_) | ModulusValue::U64(_) => {
            quote! {
                #[inline]
                fn to_root(self) -> Self::Root {
                    self
                }
            }
        }
        ModulusValue::U8(_) | ModulusValue::U16(_) => {
            quote! {
                #[inline]
                fn to_root(self) -> Self::Root {
                    Self::Root::new(self.0, #modulus)
                }
            }
        }
    }

    #[cfg(not(feature = "concrete-ntt"))]
    quote! {
        #[inline]
        fn to_root(self) -> Self::Root {
            Self::Root::new(self.0, #modulus)
        }
    }
}

#[allow(unused_variables)]
fn impl_mul_root(modulus_value: ModulusValue, modulus: &TokenStream) -> TokenStream {
    #[cfg(feature = "concrete-ntt")]
    match modulus_value {
        ModulusValue::U32(_) | ModulusValue::U64(_) => {
            quote! {
                #[inline]
                fn mul_root(self, root: Self::Root) -> Self {
                    self * root
                }
            }
        }
        ModulusValue::U8(_) | ModulusValue::U16(_) => {
            quote! {
                #[inline]
                fn mul_root(self, root: Self::Root) -> Self {
                    use ::algebra::reduce::MulReduce;
                    Self(self.0.mul_reduce(root, #modulus))
                }
            }
        }
    }

    #[cfg(not(feature = "concrete-ntt"))]
    quote! {
        #[inline]
        fn mul_root(self, root: Self::Root) -> Self {
            use ::algebra::reduce::MulReduce;
            Self(self.0.mul_reduce(root, #modulus))
        }
    }
}

#[allow(unused_variables)]
fn impl_mul_root_assign(modulus_value: ModulusValue, modulus: &TokenStream) -> TokenStream {
    #[cfg(feature = "concrete-ntt")]
    match modulus_value {
        ModulusValue::U32(_) | ModulusValue::U64(_) => {
            quote! {
                #[inline]
                fn mul_root_assign(&mut self, root: Self::Root) {
                    *self *= root;
                }
            }
        }
        ModulusValue::U8(_) | ModulusValue::U16(_) => {
            quote! {
                #[inline]
                fn mul_root_assign(&mut self, root: Self::Root) {
                    use ::algebra::reduce::MulReduceAssign;
                    self.0.mul_reduce_assign(root, #modulus);
                }
            }
        }
    }

    #[cfg(not(feature = "concrete-ntt"))]
    quote! {
        #[inline]
        fn mul_root_assign(&mut self, root: Self::Root) {
            use ::algebra::reduce::MulReduceAssign;
            self.0.mul_reduce_assign(root, #modulus);
        }
    }
}

#[allow(unused_variables)]
fn impl_generate_ntt_table(modulus_value: ModulusValue, table: &TokenStream) -> TokenStream {
    #[cfg(feature = "concrete-ntt")]
    match modulus_value {
        ModulusValue::U32(_) | ModulusValue::U64(_) => {
            quote! {
                #[inline]
                fn generate_ntt_table(log_n: u32) -> Result<Self::Table, ::algebra::AlgebraError> {
                    <#table>::new(log_n)
                }
            }
        }
        ModulusValue::U8(_) | ModulusValue::U16(_) => {
            quote! {
                fn generate_ntt_table(log_n: u32) -> Result<Self::Table, ::algebra::AlgebraError> {
                    let n = 1usize << log_n;

                    let root_one = Self(1).to_root();

                    let root = Self::try_minimal_primitive_root((n * 2).try_into().unwrap())?;

                    let root_factor = root.to_root();
                    let mut power = root;

                    let mut ordinal_root_powers = vec![Self::Root::default(); n * 2];
                    let mut iter = ordinal_root_powers.iter_mut();
                    *iter.next().unwrap() = root_one;
                    *iter.next().unwrap() = root_factor;
                    for root_power in iter {
                        power.mul_root_assign(root_factor);
                        *root_power = power.to_root();
                    }

                    Ok(Self::Table::new(
                        root,
                        log_n,
                        ordinal_root_powers,
                    ))
                }
            }
        }
    }

    #[cfg(not(feature = "concrete-ntt"))]
    quote! {
        fn generate_ntt_table(log_n: u32) -> Result<Self::Table, ::algebra::AlgebraError> {
            let n = 1usize << log_n;

            let root_one = Self(1).to_root();

            let root = Self::try_minimal_primitive_root((n * 2).try_into().unwrap())?;

            let root_factor = root.to_root();
            let mut power = root;

            let mut ordinal_root_powers = vec![Self::Root::default(); n * 2];
            let mut iter = ordinal_root_powers.iter_mut();
            *iter.next().unwrap() = root_one;
            *iter.next().unwrap() = root_factor;
            for root_power in iter {
                power.mul_root_assign(root_factor);
                *root_power = power.to_root();
            }

            Ok(Self::Table::new(
                root,
                log_n,
                ordinal_root_powers,
            ))
        }
    }
}
