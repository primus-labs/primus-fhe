use itertools::izip;
use primus_factor::FactorMul;
use primus_integer::{BigUint, BigUintIterMut, FheUint};
use primus_reduce::FieldContext;

use super::RNSBase;
use crate::Residues;

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Reconstructs the canonical representative for one residue vector.
    ///
    /// `residues.len()` must equal `moduli_count()`. Residue `i` is interpreted
    /// modulo `moduli()[i]`.
    ///
    /// The returned value has [`big_uint_value_len`](Self::big_uint_value_len)
    /// little-endian limbs and is reduced modulo the product of the basis moduli.
    ///
    /// # Panics
    ///
    /// Panics if the residue count does not match this basis.
    ///
    /// # Correctness
    ///
    /// Input residues must be canonical for the corresponding moduli.
    #[must_use]
    pub fn compose(&self, Residues(residues): Residues<&[T]>) -> BigUint<Vec<T>> {
        assert_eq!(self.moduli_count(), residues.len());

        let value_len = self.big_uint_value_len();
        let mut value = BigUint(vec![T::ZERO; value_len]);
        self.compose_to_kernel(residues, value.view_mut());
        value
    }

    /// Reconstructs into a fixed-width borrowed output after the entry point
    /// establishes the residue and limb counts. Clears all output limbs first.
    /// Each CRT term `(a_i * (Q/q_i)^-1 mod q_i) * (Q/q_i)` and the running sum
    /// are below Q, so one subtraction suffices after every add; a carry also
    /// requires subtraction when the stored limbs have wrapped.
    #[inline]
    fn compose_to_kernel(&self, residues: &[T], mut value: BigUint<&mut [T]>) {
        let moduli_product = &self.moduli_product();

        value.set_zero();

        izip!(
            residues,
            self.inv_punctured_product_mod_modulus(),
            self.iter_punctured_product(),
            self.moduli_values().iter().copied()
        )
        .for_each(|(&ai, &inv_q_div_qi_mod_qi, q_div_qi, qi_val)| {
            let product = inv_q_div_qi_mod_qi.factor_mul_modulo(ai, qi_val);
            let carry = q_div_qi.mul_value_add_to(product, &mut value);
            if !carry.is_zero() || value.cmp(moduli_product).is_ge() {
                let _ = value.sub_assign(moduli_product);
            }
        });
    }

    /// Reconstructs one residue vector into caller-provided big-integer storage.
    ///
    /// `residues.len()` must equal `moduli_count()`. Residue `i` is interpreted
    /// modulo `moduli()[i]`.
    ///
    /// `value.len()` must equal [`big_uint_value_len`](Self::big_uint_value_len).
    /// The previous contents of the buffer are fully overwritten.
    ///
    /// # Panics
    ///
    /// Panics if either storage length does not match this basis.
    ///
    /// # Correctness
    ///
    /// Input residues must be canonical for the corresponding moduli.
    pub fn compose_to(&self, Residues(residues): Residues<&[T]>, value: BigUint<&mut [T]>) {
        assert_eq!(self.moduli_count(), residues.len());
        assert_eq!(self.big_uint_value_len(), value.len());
        self.compose_to_kernel(residues, value);
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
    /// For `value_count == 0`, both data slices must be empty; scratch still
    /// has the stated length and is left unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a data or scratch length does not match the stated layout.
    ///
    /// # Correctness
    ///
    /// Input residues must be canonical for their corresponding moduli.
    pub fn compose_big_uint_values_to(
        &self,
        multi_residues: &[T],
        big_uint_values: &mut [T],
        value_count: usize,
        scratch: &mut [T],
    ) {
        assert_eq!(multi_residues.len(), self.moduli_count() * value_count);
        assert_eq!(
            big_uint_values.len(),
            self.big_uint_value_len() * value_count
        );
        assert_eq!(scratch.len(), self.moduli_count());

        let big_uint_value_len = self.big_uint_value_len();

        for (value_index, value) in
            BigUintIterMut::new(big_uint_values, big_uint_value_len).enumerate()
        {
            let mut input_index = value_index;
            for residue in scratch.iter_mut() {
                *residue = multi_residues[input_index];
                input_index += value_count;
            }
            self.compose_to_kernel(scratch, value);
        }
    }
}
