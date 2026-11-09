use primus_factor::FactorBase;
use primus_integer::{BigUint, FheUint};
use primus_reduce::FieldContext;

use super::RNSBase;
use crate::{ResidueFactors, Residues};

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Decomposes a big integer into residues modulo this basis.
    ///
    /// The input `value` is a little-endian limb slice. The returned vector has
    /// `moduli_count()` elements; element `i` is `value mod moduli()[i]`.
    /// Its limb count need not equal [`big_uint_value_len`](Self::big_uint_value_len).
    ///
    /// # Correctness
    ///
    /// Input length and empty-slice behavior follow the modulus implementation's
    /// [`Reduce::reduce`](primus_reduce::Reduce::reduce) contract.
    #[must_use]
    #[inline]
    pub fn decompose(&self, BigUint(value): BigUint<&[T]>) -> Residues<Vec<T>> {
        Residues(
            self.moduli()
                .iter()
                .map(|&modulus| modulus.reduce(value))
                .collect(),
        )
    }

    /// Decomposes a big integer into precomputed residue factors.
    ///
    /// The input `value` is a little-endian limb slice. The returned vector has
    /// `moduli_count()` factors. Factor `i` is created from `value mod q_i`
    /// and must be used only with the matching modulus `q_i == moduli()[i]`.
    /// Input requirements are the same as for [`decompose`](Self::decompose).
    #[must_use]
    #[inline]
    pub fn decompose_factors<F>(&self, BigUint(value): BigUint<&[T]>) -> ResidueFactors<Vec<F>>
    where
        F: FactorBase<T>,
    {
        ResidueFactors(
            self.moduli()
                .iter()
                .map(|&modulus| F::new(modulus.reduce(value), modulus.value()))
                .collect(),
        )
    }

    /// Decomposes a big integer into caller-provided residue storage.
    ///
    /// The input `value` is a little-endian limb slice. `residues` must contain
    /// exactly `moduli_count()` elements; element `i` receives
    /// `value mod moduli()[i]`.
    /// Its input limb count need not equal [`big_uint_value_len`](Self::big_uint_value_len).
    ///
    /// # Panics
    ///
    /// Panics if the output residue count does not match this basis.
    ///
    /// # Correctness
    ///
    /// Input requirements are the same as for [`decompose`](Self::decompose).
    #[inline]
    pub fn decompose_to(
        &self,
        BigUint(value): BigUint<&[T]>,
        Residues(residues): Residues<&mut [T]>,
    ) {
        assert_eq!(self.moduli_count(), residues.len());

        for (&modulus, residue) in self.moduli().iter().zip(residues) {
            *residue = modulus.reduce(value);
        }
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
    /// For `value_count == 0`, both slices must be empty and nothing is written.
    ///
    /// # Panics
    ///
    /// Panics if a slice length does not match the stated layout.
    pub fn decompose_big_uint_values_to(
        &self,
        big_uint_values: &[T],
        multi_residues: &mut [T],
        value_count: usize,
    ) {
        assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        assert_eq!(
            big_uint_values.len(),
            self.big_uint_value_len() * value_count
        );

        if value_count == 0 {
            return;
        }

        let value_len = self.big_uint_value_len();
        for (residues, &modulus) in multi_residues
            .chunks_exact_mut(value_count)
            .zip(self.moduli())
        {
            for (residue, value) in residues
                .iter_mut()
                .zip(big_uint_values.chunks_exact(value_len))
            {
                *residue = modulus.reduce(value);
            }
        }
    }
}
