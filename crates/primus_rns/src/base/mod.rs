mod compose;
mod decompose;
mod extension;
mod small;
mod small_kernels;

use itertools::Itertools;
use primus_factor::ShoupFactor;
use primus_integer::{BigUint, FheUint, multiply_many_values};
use primus_reduce::FieldContext;
use std::sync::Arc;

use crate::RnsError;

/// A pairwise-coprime RNS basis with CRT precomputations.
///
/// An integer is represented by one residue for each modulus in `moduli`.
/// If `Q` is the product of all moduli, the Chinese remainder theorem gives a
/// unique representative modulo `Q` for each residue vector. This type stores
/// `Q`, every punctured product `Q / q_i`, and `(Q / q_i)^-1 mod q_i`.
///
/// Batched APIs use modulus-major residue storage: for `k` values, chunk `i`
/// of length `k` stores residues modulo `moduli()[i]`.
///
/// Clones share immutable moduli and CRT precomputations through an internal Arc;
/// they neither allocate tables nor recompute them. Extending a base creates new
/// precomputations and leaves every clone of the original base unchanged.
#[derive(Clone)]
pub struct RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    inner: Arc<RNSBaseInner<T, M>>,
}

/// One immutable ordered basis and all data derived solely from its moduli.
/// Codecs, gadgets and converters share this allocation; their operation-specific
/// weights and conversion matrices remain separately owned.
struct RNSBaseInner<T: FheUint, M> {
    /// Moduli in basis order. The same order is used by every residue vector.
    moduli: Vec<M>,
    /// Contiguous numeric values for sampling and coefficient arithmetic.
    moduli_values: Vec<T>,
    /// Product `Q` of all moduli, stored as little-endian limbs.
    moduli_product: BigUint<Vec<T>>,
    /// Flattened punctured products `Q / q_i`, one `big_uint_value_len` chunk per modulus.
    punctured_product: Vec<T>,
    /// One Shoup factor for `(Q / q_i)^-1 mod q_i` per modulus.
    inv_punctured_product_mod_modulus: Vec<ShoupFactor<T>>,
}

// Form Q/q_i without big-integer division. Constructors supply enough output
// limbs for Q; only the live prefix grows as multiplication produces a carry.
fn compute_punctured_product_to<T: FheUint>(
    moduli_values: &[T],
    excluded_index: usize,
    output: &mut [T],
) {
    output.fill(T::ZERO);
    output[0] = T::ONE;
    let mut product_len = 1;

    for &modulus in moduli_values[..excluded_index]
        .iter()
        .chain(&moduli_values[excluded_index + 1..])
    {
        let carry = BigUint(&mut output[..product_len]).mul_value_assign(modulus);
        if !carry.is_zero() {
            output[product_len] = carry;
            product_len += 1;
        }
    }
}

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates an RNS basis from pairwise-coprime moduli.
    ///
    /// # Panics
    ///
    /// Panics if modular inverse computation panics unexpectedly.
    ///
    /// # Errors
    ///
    /// Returns [`RnsError::EmptyBase`] when `moduli` is empty.
    /// Returns [`RnsError::NonCoprimeModuli`] when any two moduli are not coprime.
    #[inline]
    pub fn new(moduli: &[M]) -> Result<Self, RnsError> {
        Self::from_owned_moduli(moduli.to_vec())
    }

    /// Creates an RNS basis from an owned `Vec<M>`, avoiding a clone.
    ///
    /// See [`new`](Self::new) for error conditions.
    #[inline]
    pub fn from_owned_moduli(moduli: Vec<M>) -> Result<Self, RnsError> {
        if moduli.is_empty() {
            return Err(RnsError::EmptyBase);
        }

        let moduli_values = moduli
            .iter()
            .map(|modulus| modulus.value())
            .collect::<Vec<_>>();

        if moduli.len() == 1 {
            let modulus = moduli[0];
            let value = modulus.value();
            return Ok(Self {
                inner: Arc::new(RNSBaseInner {
                    moduli,
                    moduli_values,
                    moduli_product: BigUint(vec![value]),
                    punctured_product: vec![T::ONE],
                    inv_punctured_product_mod_modulus: vec![ShoupFactor::new(T::ONE, value)],
                }),
            });
        }

        if moduli_values
            .iter()
            .array_combinations()
            .any(|[&a, &b]| !a.is_coprime(b))
        {
            return Err(RnsError::NonCoprimeModuli);
        }

        let moduli_product = multiply_many_values(&moduli_values);

        let count = moduli.len();
        let big_uint_len = moduli_product.len();
        let mut punctured_product = vec![T::ZERO; big_uint_len * count];
        punctured_product
            .chunks_exact_mut(big_uint_len)
            .enumerate()
            .for_each(|(i, q_div_qi)| {
                compute_punctured_product_to(&moduli_values, i, q_div_qi);
            });

        let inv_punctured_product_mod_modulus = punctured_product
            .chunks_exact(big_uint_len)
            .zip(&moduli)
            .zip(moduli_values.iter().copied())
            .map(|((q_div_qi, &qi), qi_value)| {
                let inv_q_div_qi_mod_qi = qi.try_reduce_inv(qi.reduce(q_div_qi)).unwrap();
                ShoupFactor::new(inv_q_div_qi_mod_qi, qi_value)
            })
            .collect::<Vec<ShoupFactor<T>>>();

        Ok(Self {
            inner: Arc::new(RNSBaseInner {
                moduli,
                moduli_values,
                moduli_product,
                punctured_product,
                inv_punctured_product_mod_modulus,
            }),
        })
    }

    /// Returns the moduli in basis order.
    #[inline]
    pub fn moduli(&self) -> &[M] {
        &self.inner.moduli
    }

    /// Returns the cached numeric moduli in the same order as [`Self::moduli`].
    /// Clones of this base borrow the same slice.
    #[must_use]
    #[inline]
    pub fn moduli_values(&self) -> &[T] {
        &self.inner.moduli_values
    }

    /// Returns the number of moduli in this basis.
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.inner.moduli.len()
    }

    /// Returns the product of all moduli as a little-endian big integer.
    #[inline]
    pub fn moduli_product(&self) -> BigUint<&[T]> {
        self.inner.moduli_product.view()
    }

    /// Returns the limb count used by composed big integers for this basis.
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.inner.moduli_product.len()
    }

    /// Iterates over punctured products `Q / q_i` as fixed-width big integers.
    ///
    /// The iterator yields `moduli_count()` chunks. Each chunk has exactly
    /// [`big_uint_value_len`](Self::big_uint_value_len) limbs.
    #[inline]
    pub(crate) fn iter_punctured_product(
        &self,
    ) -> impl ExactSizeIterator<Item = BigUint<&[T]>> + DoubleEndedIterator {
        self.inner
            .punctured_product
            .chunks_exact(self.big_uint_value_len())
            .map(BigUint)
    }

    /// Returns precomputed factors for `(Q / q_i)^-1 mod q_i`.
    ///
    /// The returned slice length is `moduli_count()`. Factor `i` belongs to
    /// `moduli()[i]` and must not be reused with another modulus.
    #[inline]
    pub(crate) fn inv_punctured_product_mod_modulus(&self) -> &[ShoupFactor<T>] {
        &self.inner.inv_punctured_product_mod_modulus
    }
}
