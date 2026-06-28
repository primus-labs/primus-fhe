use core::slice::Iter;

use itertools::{Itertools, izip};
use primus_data::{Data, DataMut, RawData};
use primus_factor::{Factor, FactorBase, FactorMul, ShoupFactor};
use primus_integer::{
    BigUint, BigUintIter, BigUintIterMut, FheUint, multiply_many_values,
    multiply_many_values_except_to,
};
use primus_modulo::prelude::*;
use primus_poly::{BigUintPolynomial, CrtPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::RNSError;

/// A pairwise-coprime RNS basis with CRT precomputations.
///
/// An integer is represented by one residue for each modulus in `moduli`.
/// If `Q` is the product of all moduli, the Chinese remainder theorem gives a
/// unique representative modulo `Q` for each residue vector. This type stores
/// `Q`, every punctured product `Q / q_i`, and `(Q / q_i)^-1 mod q_i`.
///
/// Batched APIs use modulus-major residue storage: for `k` values, chunk `i`
/// of length `k` stores residues modulo `moduli()[i]`.
#[derive(Clone)]
pub struct RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Moduli in basis order. The same order is used by every residue vector.
    moduli: Vec<M>,
    /// Product `Q` of all moduli, stored as little-endian limbs.
    moduli_product: BigUint<Vec<T>>,
    /// Flattened punctured products `Q / q_i`, one `big_uint_value_len` chunk per modulus.
    punctured_product: Vec<T>,
    /// One Shoup factor for `(Q / q_i)^-1 mod q_i` per modulus.
    inv_punctured_product_mod_modulus: Vec<ShoupFactor<T>>,
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
    /// Panics if `moduli` is empty, if a modulus implementation cannot return
    /// a representable value from `value_unchecked`, or if modular inverse
    /// computation panics unexpectedly.
    ///
    /// # Errors
    ///
    /// Returns [`RNSError::CoPrimeError`] when any two moduli are not coprime.
    #[inline]
    pub fn new(moduli: &[M]) -> Result<Self, RNSError> {
        let moduli_values = moduli
            .iter()
            .map(|m| unsafe { m.value_unchecked() })
            .collect::<Vec<_>>();

        if moduli_values
            .iter()
            .array_combinations()
            .any(|[&a, &b]| !a.is_coprime(b))
        {
            return Err(RNSError::CoPrimeError);
        }

        let moduli_product = multiply_many_values(&moduli_values);

        let big_uint_len = moduli_product.len();
        let mut punctured_product = vec![T::ZERO; big_uint_len * moduli.len()];
        punctured_product
            .chunks_exact_mut(big_uint_len)
            .enumerate()
            .for_each(|(i, chunk)| {
                multiply_many_values_except_to(&moduli_values, i, chunk);
            });

        let inv_punctured_product_mod_modulus = punctured_product
            .chunks_exact(big_uint_len)
            .zip(moduli)
            .map(|(p, &modulus)| {
                let inv = p.modulo(modulus).try_inv_modulo(modulus).unwrap();
                ShoupFactor::new(inv, unsafe { modulus.value_unchecked() })
            })
            .collect::<Vec<ShoupFactor<T>>>();

        Ok(Self {
            moduli: moduli.to_vec(),
            moduli_product,
            punctured_product,
            inv_punctured_product_mod_modulus,
        })
    }

    /// Returns the moduli in basis order.
    #[inline]
    pub fn moduli(&self) -> &[M] {
        &self.moduli
    }

    /// Returns the number of moduli in this basis.
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.moduli.len()
    }

    /// Returns the product of all moduli as a little-endian big integer.
    #[inline]
    pub fn moduli_product(&self) -> BigUint<&[T]> {
        self.moduli_product.view()
    }

    /// Returns the limb count used by composed big integers for this basis.
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.moduli_product.len()
    }

    /// Returns all punctured products in flattened basis order.
    ///
    /// The returned slice length is `moduli_count() * big_uint_value_len()`.
    /// Chunk `i` has length [`big_uint_value_len`](Self::big_uint_value_len)
    /// and stores `Q / q_i`, where `q_i == moduli()[i]`.
    #[inline]
    pub fn punctured_product(&self) -> &[T] {
        &self.punctured_product
    }

    /// Iterates over punctured products `Q / q_i` as big-integer limb slices.
    ///
    /// The iterator yields `moduli_count()` chunks. Each chunk has exactly
    /// [`big_uint_value_len`](Self::big_uint_value_len) limbs.
    #[inline]
    pub fn iter_punctured_product(&self) -> core::slice::ChunksExact<'_, T> {
        self.punctured_product
            .chunks_exact(self.big_uint_value_len())
    }

    /// Returns precomputed factors for `(Q / q_i)^-1 mod q_i`.
    ///
    /// The returned slice length is `moduli_count()`. Factor `i` belongs to
    /// `moduli()[i]` and must not be reused with another modulus.
    #[inline]
    pub fn inv_punctured_product_mod_modulus(&self) -> &[ShoupFactor<T>] {
        &self.inv_punctured_product_mod_modulus
    }

    /// Decomposes a big integer into residues modulo this basis.
    ///
    /// The input `value` is a little-endian limb slice. The returned vector has
    /// `moduli_count()` elements; element `i` is `value mod moduli()[i]`.
    #[inline]
    pub fn decompose(&self, BigUint(value): BigUint<&[T]>) -> Vec<T> {
        self.moduli
            .iter()
            .map(|&modulus| value.modulo(modulus))
            .collect()
    }

    /// Decomposes a big integer into precomputed residue factors.
    ///
    /// The input `value` is a little-endian limb slice. The returned vector has
    /// `moduli_count()` factors. Factor `i` is created from `value mod q_i`
    /// and must be used only with the matching modulus `q_i == moduli()[i]`.
    #[inline]
    pub fn decompose_to_rns_factor<F>(&self, BigUint(value): BigUint<&[T]>) -> Vec<F>
    where
        F: FactorBase<T>,
    {
        self.moduli
            .iter()
            .map(|&modulus| F::new(value.modulo(modulus), unsafe { modulus.value_unchecked() }))
            .collect()
    }

    /// Decomposes one small value with centered wrapping semantics.
    ///
    /// The returned vector has `moduli_count()` residues. The input `value` is
    /// expected to be reduced modulo `small_value_modulus`. Values below
    /// `ceil(small_value_modulus / 2)` are copied as positive residues. Other
    /// values are interpreted as negative representatives modulo
    /// `small_value_modulus` and lifted into each RNS modulus.
    ///
    /// `small_value_modulus` must be no larger than every RNS modulus; batched
    /// variants require it to be strictly smaller in debug builds.
    pub fn wrapping_decompose(&self, value: T, small_value_modulus: T) -> Vec<T> {
        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            self.moduli
                .iter()
                .map(|m| unsafe { m.value_unchecked() })
                .map(|modulus| {
                    if value < half {
                        value
                    } else {
                        modulus - small_value_modulus + value
                    }
                })
                .collect()
        } else {
            vec![value; self.moduli_count()]
        }
    }

    /// Decomposes a big integer into caller-provided residue storage.
    ///
    /// The input `value` is a little-endian limb slice. `residues` must contain
    /// exactly `moduli_count()` elements; element `i` receives
    /// `value mod moduli()[i]`.
    #[inline]
    pub fn decompose_to(&self, BigUint(value): BigUint<&[T]>, residues: &mut [T]) {
        debug_assert_eq!(self.moduli_count(), residues.len());

        for (&modulus, residue) in self.moduli.iter().zip(residues) {
            *residue = value.modulo(modulus);
        }
    }

    /// Writes [`wrapping_decompose`](Self::wrapping_decompose) into caller-provided storage.
    ///
    /// `residues` must contain exactly `moduli_count()` elements. `value` is
    /// expected to be reduced modulo `small_value_modulus`; the output uses the
    /// same basis order as [`moduli`](Self::moduli).
    pub fn wrapping_decompose_to(&self, value: T, residues: &mut [T], small_value_modulus: T) {
        debug_assert_eq!(self.moduli_count(), residues.len());

        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            self.moduli
                .iter()
                .map(|m| unsafe { m.value_unchecked() })
                .zip(residues)
                .for_each(|(modulus, residue)| {
                    *residue = if value < half {
                        value
                    } else {
                        modulus - small_value_modulus + value
                    };
                });
        } else {
            residues.fill(value);
        }
    }

    /// Decomposes many small values into a flattened multi-residue layout.
    ///
    /// `small_values.len()` must equal `value_count`. Each value is expected to
    /// be reduced modulo `small_value_modulus`.
    ///
    /// `multi_residues.len()` must equal `moduli_count() * value_count` and is
    /// written in modulus-major layout: chunk `i` of length `value_count`
    /// receives all values reduced modulo `moduli()[i]`.
    ///
    /// `small_value_modulus` must be smaller than every RNS modulus.
    pub fn wrapping_decompose_small_values_to(
        &self,
        small_values: &[T],
        multi_residues: &mut [T],
        value_count: usize,
        small_value_modulus: T,
    ) {
        debug_assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        debug_assert_eq!(small_values.len(), value_count);
        debug_assert!(
            self.moduli
                .iter()
                .all(|m| unsafe { m.value_unchecked() } > small_value_modulus)
        );
        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            for (residues, modulus) in multi_residues
                .chunks_exact_mut(value_count)
                .zip(self.moduli().iter().map(|m| unsafe { m.value_unchecked() }))
            {
                let temp = modulus - small_value_modulus;

                #[cfg(not(feature = "simd"))]
                slice::wrapping_decompose_chunk_to(small_values, residues, half, temp);

                #[cfg(feature = "simd")]
                simd::wrapping_decompose_chunk_to(small_values, residues, half, temp);
            }
        } else {
            for residues in multi_residues.chunks_exact_mut(value_count) {
                residues.copy_from_slice(small_values);
            }
        }
    }

    /// Fused centered decomposition, scaling, and accumulation for small values.
    ///
    /// `small_values.len()` must equal `value_count`. Each value is expected to
    /// be reduced modulo `small_value_modulus`, which must be smaller than
    /// every RNS modulus.
    ///
    /// `acc.len()` must equal `moduli_count() * value_count` and uses
    /// modulus-major layout. The function adds into the existing contents of
    /// `acc`; it does not clear the buffer first.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    pub fn add_wrapping_decompose_small_values_scaled<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        value_count: usize,
        small_value_modulus: T,
        factors: &[F],
    ) {
        debug_assert_eq!(acc.len(), self.moduli_count() * value_count);
        debug_assert_eq!(small_values.len(), value_count);
        debug_assert_eq!(factors.len(), self.moduli_count());
        debug_assert!(
            self.moduli
                .iter()
                .all(|m| unsafe { m.value_unchecked() } > small_value_modulus)
        );

        if small_value_modulus != T::TWO {
            let half = (small_value_modulus + T::ONE) / T::TWO;
            izip!(
                acc.chunks_exact_mut(value_count),
                self.moduli().iter().map(|m| unsafe { m.value_unchecked() }),
                factors,
            )
            .for_each(|(acc_chunk, modulus, &factor)| {
                let temp = modulus - small_value_modulus;

                #[cfg(not(feature = "simd"))]
                slice::wrapping_decompose_chunk_scaled_to(
                    small_values,
                    acc_chunk,
                    half,
                    temp,
                    modulus,
                    factor,
                );

                #[cfg(feature = "simd")]
                simd::wrapping_decompose_chunk_scaled_to(
                    small_values,
                    acc_chunk,
                    half,
                    temp,
                    modulus,
                    factor,
                );
            });
        } else {
            izip!(
                acc.chunks_exact_mut(value_count),
                self.moduli().iter().map(|m| unsafe { m.value_unchecked() }),
                factors,
            )
            .for_each(|(acc_chunk, _modulus, &factor)| {
                factor.add_factor_mul_slice_assign(acc_chunk, small_values, _modulus);
            });
        }
    }

    /// Fused unsigned decomposition, scaling, and accumulation for small values.
    ///
    /// Unlike [`add_wrapping_decompose_small_values_scaled`](Self::add_wrapping_decompose_small_values_scaled), this does
    /// unsigned decomposition: each input value is used directly as a residue
    /// under every modulus, without centered lifting. Callers should pass
    /// values that are already valid residues for all basis moduli.
    ///
    /// `small_values.len()` must equal `value_count`. `acc.len()` must equal
    /// `moduli_count() * value_count` and uses modulus-major layout. The
    /// function adds into the existing contents of `acc`.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    pub fn add_decompose_small_values_scaled<F: Factor<T>>(
        &self,
        small_values: &[T],
        acc: &mut [T],
        value_count: usize,
        factors: &[F],
    ) {
        debug_assert_eq!(acc.len(), self.moduli_count() * value_count);
        debug_assert_eq!(small_values.len(), value_count);
        debug_assert_eq!(factors.len(), self.moduli_count());

        izip!(
            acc.chunks_exact_mut(value_count),
            self.moduli().iter().map(|m| unsafe { m.value_unchecked() }),
            factors,
        )
        .for_each(|(acc_chunk, modulus, &factor)| {
            factor.add_factor_mul_slice_assign(acc_chunk, small_values, modulus);
        });
    }

    /// Adds an unsigned small polynomial decomposition scaled by per-modulus factors.
    ///
    /// `small_poly.as_slice().len()` must equal `poly_length`.
    /// `acc.as_mut_slice().len()` must equal `moduli_count() * poly_length`
    /// and uses modulus-major CRT polynomial layout.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// output chunk modulo `moduli()[i]`. The function accumulates into `acc`
    /// without clearing it first.
    #[inline]
    pub fn add_decompose_small_polynomial_scaled<F: Factor<T>, A, C>(
        &self,
        small_poly: &Polynomial<A>,
        acc: &mut CrtPolynomial<C>,
        poly_length: usize,
        factors: &[F],
    ) where
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        self.add_decompose_small_values_scaled(
            small_poly.as_slice(),
            acc.as_mut_slice(),
            poly_length,
            factors,
        );
    }

    /// Decomposes many big integers into a flattened multi-residue layout.
    ///
    /// `big_uint_values.len()` must equal
    /// `value_count * big_uint_value_len()`. It stores `value_count`
    /// consecutive little-endian integers, each with
    /// [`big_uint_value_len`](Self::big_uint_value_len) limbs.
    ///
    /// `multi_residues.len()` must equal `moduli_count() * value_count` and is
    /// written in modulus-major layout: chunk `i` of length `value_count`
    /// receives all values reduced modulo `moduli()[i]`.
    pub fn decompose_big_uint_values_to(
        &self,
        big_uint_values: &[T],
        multi_residues: &mut [T],
        value_count: usize,
    ) {
        debug_assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        debug_assert_eq!(
            big_uint_values.len(),
            self.big_uint_value_len() * value_count
        );

        let value_len = self.big_uint_value_len();
        for (residues, &modulus) in multi_residues
            .chunks_exact_mut(value_count)
            .zip(self.moduli())
        {
            for (residue, value) in residues
                .iter_mut()
                .zip(big_uint_values.chunks_exact(value_len))
            {
                *residue = value.modulo(modulus);
            }
        }
    }

    /// Decomposes a small polynomial into CRT form with centered wrapping semantics.
    ///
    /// `small_poly.as_slice().len()` must equal `poly_length`. Coefficients are
    /// expected to be reduced modulo `small_poly_modulus`.
    ///
    /// `crt_poly.as_mut_slice().len()` must equal `moduli_count() * poly_length`
    /// and is written in modulus-major layout: chunk `i` of length
    /// `poly_length` receives coefficients reduced modulo `moduli()[i]`.
    #[inline]
    pub fn wrapping_decompose_small_polynomial_to<A, B>(
        &self,
        small_poly: &Polynomial<A>,
        crt_poly: &mut CrtPolynomial<B>,
        poly_length: usize,
        small_poly_modulus: T,
    ) where
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.wrapping_decompose_small_values_to(
            small_poly.as_slice(),
            crt_poly.as_mut_slice(),
            poly_length,
            small_poly_modulus,
        );
    }

    /// Adds a centered small-polynomial decomposition scaled by per-modulus factors.
    ///
    /// `small_poly.as_slice().len()` must equal `poly_length`. Coefficients are
    /// expected to be reduced modulo `small_poly_modulus`.
    ///
    /// `acc.as_mut_slice().len()` must equal `moduli_count() * poly_length` and
    /// uses modulus-major CRT polynomial layout. The function accumulates into
    /// `acc` without clearing it first.
    ///
    /// `factors.len()` must equal `moduli_count()`. Factor `i` is used for the
    /// chunk modulo `moduli()[i]`.
    #[inline]
    pub fn add_wrapping_decompose_small_polynomial_scaled<F: Factor<T>, A, C>(
        &self,
        small_poly: &Polynomial<A>,
        acc: &mut CrtPolynomial<C>,
        poly_length: usize,
        small_poly_modulus: T,
        factors: &[F],
    ) where
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        self.add_wrapping_decompose_small_values_scaled(
            small_poly.as_slice(),
            acc.as_mut_slice(),
            poly_length,
            small_poly_modulus,
            factors,
        );
    }

    /// Decomposes a polynomial with big-integer coefficients into CRT form.
    ///
    /// `big_uint_poly.as_slice().len()` must equal
    /// `poly_length * big_uint_value_len()`. It stores `poly_length`
    /// consecutive little-endian coefficients.
    ///
    /// `crt_poly.as_mut_slice().len()` must equal `moduli_count() * poly_length`
    /// and is written in modulus-major layout.
    #[inline]
    pub fn decompose_polynomial_to<A, B>(
        &self,
        big_uint_poly: &BigUintPolynomial<A>,
        crt_poly: &mut CrtPolynomial<B>,
        poly_length: usize,
    ) where
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.decompose_big_uint_values_to(
            big_uint_poly.as_slice(),
            crt_poly.as_mut_slice(),
            poly_length,
        );
    }

    /// Reconstructs the canonical representative for one residue vector.
    ///
    /// `residues.len()` must equal `moduli_count()`. Residue `i` is interpreted
    /// modulo `moduli()[i]`.
    ///
    /// The returned value has [`big_uint_value_len`](Self::big_uint_value_len)
    /// little-endian limbs and is reduced modulo the product of the basis moduli.
    pub fn compose(&self, residues: &[T]) -> BigUint<Vec<T>> {
        debug_assert_eq!(self.moduli_count(), residues.len());

        let value_len = self.big_uint_value_len();
        let moduli_product = &self.moduli_product();

        let mut value = BigUint(vec![T::ZERO; value_len]);

        izip!(
            residues,
            &self.inv_punctured_product_mod_modulus,
            BigUintIter::new(&self.punctured_product, value_len),
            &self.moduli
        )
        .for_each(
            |(&ri, &inv_mi, mi, &modulus): (&T, &ShoupFactor<T>, BigUint<&[T]>, &M)| {
                let product = inv_mi.factor_mul_modulo(ri, unsafe { modulus.value_unchecked() });
                let carry = mi.mul_value_add_to(product, &mut value);
                if !carry.is_zero() || value.cmp(moduli_product).is_ge() {
                    let _ = value.sub_assign(moduli_product);
                }
            },
        );

        value
    }

    /// Reconstructs one residue vector into caller-provided big-integer storage.
    ///
    /// `residues.len()` must equal `moduli_count()`. Residue `i` is interpreted
    /// modulo `moduli()[i]`.
    ///
    /// `value.len()` must equal [`big_uint_value_len`](Self::big_uint_value_len).
    /// The buffer is cleared before the composed canonical representative is
    /// written into it.
    pub fn compose_to(&self, residues: &[T], value: &mut BigUint<&mut [T]>) {
        debug_assert_eq!(self.moduli_count(), residues.len());
        debug_assert_eq!(self.big_uint_value_len(), value.len());

        let value_len = self.moduli_product.len();
        let moduli_product = &self.moduli_product();

        value.set_zero();

        izip!(
            residues,
            &self.inv_punctured_product_mod_modulus,
            BigUintIter::new(&self.punctured_product, value_len),
            &self.moduli
        )
        .for_each(
            |(&ri, &inv_mi, mi, &modulus): (&T, &ShoupFactor<T>, BigUint<&[T]>, &M)| {
                let product = inv_mi.factor_mul_modulo(ri, unsafe { modulus.value_unchecked() });
                let carry = mi.mul_value_add_to(product, value);
                if !carry.is_zero() || value.cmp(moduli_product).is_ge() {
                    let _ = value.sub_assign(moduli_product);
                }
            },
        );
    }

    /// Reconstructs many values from a flattened multi-residue layout.
    ///
    /// `multi_residues.len()` must equal `moduli_count() * value_count` and is
    /// read in modulus-major layout: chunk `i` of length `value_count` contains
    /// residues modulo `moduli()[i]`.
    ///
    /// `big_uint_values.len()` must equal
    /// `value_count * big_uint_value_len()`. It receives `value_count`
    /// consecutive little-endian integers, each with
    /// [`big_uint_value_len`](Self::big_uint_value_len) limbs.
    ///
    /// `scratch.len()` must equal `moduli_count()`. It is scratch storage for
    /// one coefficient's residue vector and is overwritten for each value.
    pub fn compose_multiple_values_to(
        &self,
        multi_residues: &[T],
        big_uint_values: &mut [T],
        value_count: usize,
        scratch: &mut [T],
    ) {
        debug_assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        debug_assert_eq!(
            big_uint_values.len(),
            self.big_uint_value_len() * value_count
        );
        debug_assert_eq!(scratch.len(), self.moduli_count());

        let big_uint_value_len = self.big_uint_value_len();

        let mut iters: Vec<Iter<'_, T>> = multi_residues
            .chunks_exact(value_count)
            .map(|s| s.iter())
            .collect();

        for ref mut value in BigUintIterMut::new(big_uint_values, big_uint_value_len) {
            for (iter, residue) in iters.iter_mut().zip(scratch.iter_mut()) {
                *residue = *iter.next().unwrap();
            }
            self.compose_to(scratch, value);
        }
    }

    /// Reconstructs a CRT polynomial into big-integer coefficient form.
    ///
    /// `crt_poly.as_slice().len()` must equal `moduli_count() * poly_length`
    /// and is read in modulus-major layout.
    ///
    /// `big_uint_poly.as_mut_slice().len()` must equal
    /// `poly_length * big_uint_value_len()`. It receives `poly_length`
    /// consecutive little-endian coefficients.
    ///
    /// `scratch.len()` must equal `moduli_count()`. It stores one coefficient's
    /// residue vector while composing each coefficient.
    #[inline]
    pub fn compose_polynomial_to<A, B>(
        &self,
        crt_poly: &CrtPolynomial<A>,
        big_uint_poly: &mut BigUintPolynomial<B>,
        poly_length: usize,
        scratch: &mut [T],
    ) where
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        self.compose_multiple_values_to(
            crt_poly.as_slice(),
            big_uint_poly.as_mut_slice(),
            poly_length,
            scratch,
        );
    }
}

mod slice {
    //! Scalar helper kernels for one modulus chunk.

    use primus_factor::Factor;
    use primus_integer::FheUint;
    use primus_modulus::common::compact;

    /// Writes one centered small-value chunk for a single RNS modulus.
    ///
    /// `small_values.len()` and `residues.len()` must match. `residues` is the
    /// output chunk for one modulus. `half` is `ceil(small_value_modulus / 2)`
    /// and `temp` is `modulus - small_value_modulus` for that modulus.
    #[inline]
    pub(super) fn wrapping_decompose_chunk_to<T: FheUint>(
        small_values: &[T],
        residues: &mut [T],
        half: T,
        temp: T,
    ) {
        for (residue, &value) in residues.iter_mut().zip(small_values) {
            *residue = if value < half { value } else { temp + value };
        }
    }

    /// Adds one centered, scaled small-value chunk for a single RNS modulus.
    ///
    /// `small_values.len()` and `acc.len()` must match. `acc` is the
    /// accumulator chunk for one modulus and is not cleared. `factor` must be a
    /// factor for `modulus`. `half` and `temp` have the same meaning as in
    /// [`wrapping_decompose_chunk_to`].
    #[inline]
    pub(super) fn wrapping_decompose_chunk_scaled_to<T, F>(
        small_values: &[T],
        acc: &mut [T],
        half: T,
        temp: T,
        modulus: T,
        factor: F,
    ) where
        T: FheUint,
        F: Factor<T>,
    {
        for (d, &value) in acc.iter_mut().zip(small_values) {
            let centered = if value < half { value } else { temp + value };
            compact::reduce_add_assign(modulus, d, factor.factor_mul_modulo(centered, modulus));
        }
    }
}

#[cfg(feature = "simd")]
mod simd {
    //! SIMD helper kernels for one modulus chunk.

    use std::simd::cmp::{SimdOrd, SimdPartialOrd};

    use primus_factor::{Factor, FactorMul};
    use primus_integer::{FheUint, SimdArray, SimdMaskArray};

    /// Vectorized centered small-value decomposition for one RNS modulus.
    ///
    /// `small_values.len()` and `residues.len()` must match. Full SIMD lanes
    /// are processed here and any remainder is delegated to the scalar helper.
    /// `half` and `temp` have the same meaning as in the scalar helper.
    #[inline]
    pub(super) fn wrapping_decompose_chunk_to<T: FheUint>(
        small_values: &[T],
        residues: &mut [T],
        half: T,
        temp: T,
    ) {
        let half_simd = T::SimdT::splat(half);
        let temp_simd = T::SimdT::splat(temp);

        let (res_chunks, res_rem) = T::simd_as_chunks_mut(residues);
        let (val_chunks, val_rem) = T::simd_as_chunks(small_values);

        for (res, val) in res_chunks.iter_mut().zip(val_chunks) {
            let v = T::SimdT::from_array(*val);
            let mask = v.simd_lt(half_simd);
            *res = mask.select(v, temp_simd + v).to_array();
        }

        super::slice::wrapping_decompose_chunk_to(val_rem, res_rem, half, temp);
    }

    /// Vectorized centered, scaled accumulation for one RNS modulus.
    ///
    /// `small_values.len()` and `acc.len()` must match. Full SIMD lanes are
    /// accumulated here and any remainder is delegated to the scalar helper.
    /// `factor` must be a factor for `modulus`.
    #[inline]
    pub(super) fn wrapping_decompose_chunk_scaled_to<T, F>(
        small_values: &[T],
        acc: &mut [T],
        half: T,
        temp: T,
        modulus: T,
        factor: F,
    ) where
        T: FheUint,
        F: Factor<T>,
    {
        let sh = T::SimdT::splat(half);
        let st = T::SimdT::splat(temp);
        let sm = T::SimdT::splat(modulus);
        let sf = F::simd_from_factor(factor);

        let (acc_chunks, acc_rem) = T::simd_as_chunks_mut(acc);
        let (val_chunks, val_rem) = T::simd_as_chunks(small_values);

        for (acc_chunk, val_chunk) in acc_chunks.iter_mut().zip(val_chunks) {
            let v = T::SimdT::from_array(*val_chunk);
            let mask = v.simd_lt(sh);
            let centered = mask.select(v, st + v);
            let product = sf.factor_mul_modulo(centered, sm);
            let acc_val = T::SimdT::from_array(*acc_chunk);
            let sum = acc_val + product;
            *acc_chunk = sum.simd_min(sum - sm).to_array();
        }

        super::slice::wrapping_decompose_chunk_scaled_to(
            val_rem, acc_rem, half, temp, modulus, factor,
        );
    }
}
