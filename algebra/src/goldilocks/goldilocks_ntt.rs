use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use num_traits::{pow, Zero};
use rand::{distributions, thread_rng};

use crate::{transformation::prime64::ConcreteTable, Field, NTTField, NegOne};

use super::Goldilocks;

impl From<usize> for Goldilocks {
    #[inline]
    fn from(value: usize) -> Self {
        let modulus = Goldilocks::MODULUS_VALUE as usize;
        if value < modulus {
            Self(value as u64)
        } else {
            Self((value - modulus) as u64)
        }
    }
}

static mut NTT_TABLE: once_cell::sync::OnceCell<
    HashMap<u32, Arc<<Goldilocks as NTTField>::Table>>,
> = once_cell::sync::OnceCell::new();

static NTT_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl NTTField for Goldilocks {
    type Table = ConcreteTable<Self>;

    type Root = Self;

    type Degree = u64;

    #[inline]
    fn from_root(root: Self::Root) -> Self {
        root
    }

    #[inline]
    fn to_root(self) -> Self::Root {
        self
    }

    #[inline]
    fn mul_root(self, root: Self::Root) -> Self {
        self * root
    }

    #[inline]
    fn mul_root_assign(&mut self, root: Self::Root) {
        *self *= root
    }

    #[inline]
    fn is_primitive_root(root: Self, degree: Self::Degree) -> bool {
        debug_assert!(
            degree > 1 && degree.is_power_of_two(),
            "degree must be a power of two and bigger than 1"
        );

        if root == Self::zero() {
            return false;
        }

        pow(root, (degree >> 1) as usize) == Self::neg_one()
    }

    fn try_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError> {
        let modulus_sub_one = Goldilocks::MODULUS_VALUE - 1;
        let quotient = modulus_sub_one / degree;
        if modulus_sub_one != quotient * degree {
            return Err(crate::AlgebraError::NoPrimitiveRoot {
                degree: degree.to_string(),
                modulus: Goldilocks::MODULUS_VALUE.to_string(),
            });
        }

        let mut rng = thread_rng();
        let distr = distributions::Uniform::new_inclusive(2, modulus_sub_one);

        let mut w = Self::zero();

        if (0..100).any(|_| {
            w = pow(
                Self::new(rand::Rng::sample(&mut rng, distr)),
                quotient as usize,
            );
            Self::is_primitive_root(w, degree)
        }) {
            Ok(w)
        } else {
            Err(crate::AlgebraError::NoPrimitiveRoot {
                degree: degree.to_string(),
                modulus: Goldilocks::MODULUS_VALUE.to_string(),
            })
        }
    }

    fn try_minimal_primitive_root(degree: Self::Degree) -> Result<Self, crate::AlgebraError> {
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

    #[inline]
    fn generate_ntt_table(log_n: u32) -> Result<Self::Table, crate::AlgebraError> {
        Self::Table::new(log_n)
    }

    fn init_ntt_table(log_ns: &[u32]) -> Result<(), crate::AlgebraError> {
        let _g = NTT_MUTEX.lock().unwrap();
        match unsafe { NTT_TABLE.get_mut() } {
            Some(tables) => {
                let new_log_ns: HashSet<u32> = log_ns.iter().copied().collect();
                let old_log_ns: HashSet<u32> = tables.keys().copied().collect();

                let difference = new_log_ns.difference(&old_log_ns);

                for &log_n in difference {
                    let temp_table = Self::generate_ntt_table(log_n)?;
                    tables.insert(log_n, Arc::new(temp_table));
                }
                Ok(())
            }
            None => {
                let log_ns: HashSet<u32> = log_ns.iter().copied().collect();
                let mut map = HashMap::with_capacity(log_ns.len());

                for log_n in log_ns {
                    let temp_table = Self::generate_ntt_table(log_n)?;
                    map.insert(log_n, Arc::new(temp_table));
                }

                if unsafe { NTT_TABLE.set(map).is_err() } {
                    Err(crate::AlgebraError::NTTTableError)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn get_ntt_table(log_n: u32) -> Result<Arc<Self::Table>, crate::AlgebraError> {
        if let Some(tables) = unsafe { NTT_TABLE.get() } {
            if let Some(t) = tables.get(&log_n) {
                return Ok(Arc::clone(t));
            }
        }

        Self::init_ntt_table(&[log_n])?;
        Ok(Arc::clone(unsafe {
            NTT_TABLE.get().unwrap().get(&log_n).unwrap()
        }))
    }
}

#[test]
fn ntt_test() {
    use crate::{NTTPolynomial, Polynomial};
    let n = 1 << 10;
    let mut rng = thread_rng();
    let poly = Polynomial::<Goldilocks>::random(n, &mut rng);

    let ntt_poly: NTTPolynomial<Goldilocks> = poly.clone().into();

    let expect_poly: Polynomial<Goldilocks> = ntt_poly.into();
    assert_eq!(poly, expect_poly);
}
