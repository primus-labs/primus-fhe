use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, Result};

use crate::ast::Input;

#[inline]
pub(super) fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let input = Input::from_syn(input)?;
    Ok(impl_ntt(input))
}

fn impl_ntt(input: Input) -> TokenStream {
    let name = &input.ident;
    let field_ty = input.field.ty;
    let modulus = input.attrs.modulus.unwrap();

    let ntt_table = format_ident!("NTT_TABLE{}", name.to_string().to_uppercase());
    let ntt_mutex = format_ident!("NTT_MUTEX{}", name.to_string().to_uppercase());

    quote! {
        static mut #ntt_table: ::once_cell::sync::OnceCell<::std::collections::HashMap<u32, ::std::sync::Arc<::algebra::transformation::NTTTable<#name>>>>
            = ::once_cell::sync::OnceCell::new();
        static #ntt_mutex: ::std::sync::Mutex<()> = ::std::sync::Mutex::new(());

        impl ::algebra::NTTField for #name {
            type Table = ::algebra::transformation::NTTTable<Self>;

            type Root = ::algebra::modulus::MulReduceFactor<<Self as ::algebra::Field>::Inner>;

            type Degree = #field_ty;

            #[inline]
            fn from_root(root: Self::Root) -> Self {
                #name(root.value())
            }

            #[inline]
            fn to_root(self) -> Self::Root {
                Self::Root::new(self.0, (((self.0 as <#field_ty as ::algebra::Widening>::WideT) << #field_ty::BITS) / #modulus as <#field_ty as ::algebra::Widening>::WideT) as #field_ty)
            }

            #[inline]
            fn mul_root(self, root: Self::Root) -> Self {
                use ::algebra::reduce::MulReduce;
                Self(self.0.mul_reduce(root, #modulus))
            }

            #[inline]
            fn mul_root_assign(&mut self, root: Self::Root) {
                use ::algebra::reduce::MulReduceAssign;
                self.0.mul_reduce_assign(root, #modulus);
            }

            #[inline]
            fn is_primitive_root(root: Self, degree: Self::Degree) -> bool {
                debug_assert!(root.0 < #modulus);
                debug_assert!(
                    degree > 1 && degree.is_power_of_two(),
                    "degree must be a power of two and bigger than 1"
                );

                if ::num_traits::Zero::is_zero(&root) {
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
                let distr = ::rand::distributions::Uniform::new_inclusive(Self(2), Self(#modulus - 1));

                let mut w = Self(0);

                if (0..100).any(|_| {
                    w = ::num_traits::Pow::pow(::rand::Rng::sample(&mut rng, distr), quotient);
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

                let generator_sq = ::algebra::Field::square(root);
                let mut current_generator = root;

                for _ in 0..degree {
                    if current_generator < root {
                        root = current_generator;
                    }

                    current_generator *= generator_sq;
                }

                Ok(root)
            }

            fn generate_ntt_table(log_n: u32) -> Result<::algebra::transformation::NTTTable<Self>, ::algebra::AlgebraError> {
                let n = 1usize << log_n;

                let root = Self::try_minimal_primitive_root((n * 2).try_into().unwrap())?;
                let inv_root = ::num_traits::Inv::inv(root);

                let root_factor = root.to_root();
                let mut power = root;

                let mut root_powers = vec![<Self as ::algebra::NTTField>::Root::default(); n];
                root_powers[0] = Self(1).to_root();
                for i in 1..n {
                    root_powers[::algebra::utils::ReverseLsbs::reverse_lsbs(i, log_n)] = power.to_root();
                    power.mul_root_assign(root_factor);
                }

                let inv_root_factor = inv_root.to_root();
                let mut inv_root_powers = vec![<Self as ::algebra::NTTField>::Root::default(); n];
                power = inv_root;

                inv_root_powers[0] = Self(1).to_root();
                for i in 1..n {
                    inv_root_powers[::algebra::utils::ReverseLsbs::reverse_lsbs(i - 1, log_n) + 1] = power.to_root();
                    power.mul_root_assign(inv_root_factor);
                }
                let inv_degree = ::num_traits::Inv::inv(Self(n as #field_ty)).to_root();

                Ok(::algebra::transformation::NTTTable::new(
                    root,
                    inv_root,
                    log_n,
                    n,
                    inv_degree,
                    root_powers,
                    inv_root_powers,
                ))
            }

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
