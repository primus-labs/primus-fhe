use crate::{Basis, DecomposableField};

use super::Polynomial;

impl<F: DecomposableField> Polynomial<F> {
    /// Decompose `self` according to `basis`.
    pub fn decompose(mut self, basis: Basis<F>) -> Vec<Self> {
        let mask = basis.mask();
        let bits = basis.bits();

        (0..basis.decompose_len())
            .map(|_| {
                let data: Vec<F> = self
                    .iter_mut()
                    .map(|v| v.decompose_lsb_bits(mask, bits))
                    .collect();
                <Polynomial<F>>::new(data)
            })
            .collect()
    }

    /// Decompose `self` according to `basis`.
    ///
    /// # Attention
    ///
    /// **`self`** will be a **zero** polynomial *after* performing this decomposition.
    pub fn decompose_inplace(&mut self, basis: Basis<F>, destination: &mut [Self]) {
        assert_eq!(destination.len(), basis.decompose_len());

        let mask = basis.mask();
        let bits = basis.bits();

        destination.iter_mut().for_each(|d_poly| {
            debug_assert_eq!(d_poly.coeff_count(), self.coeff_count());
            d_poly
                .into_iter()
                .zip(self.iter_mut())
                .for_each(|(d_i, p_i)| {
                    p_i.decompose_lsb_bits_at(d_i, mask, bits);
                })
        });
    }

    /// Decompose `self` according to `basis`.
    ///
    /// # Attention
    ///
    /// **`self`** will be modified *after* performing this decomposition.
    pub fn decompose_lsb_bits_inplace(&mut self, basis: Basis<F>, destination: &mut [F]) {
        debug_assert_eq!(destination.len(), self.coeff_count());
        let mask = basis.mask();
        let bits = basis.bits();

        destination.iter_mut().zip(self).for_each(|(d_i, p_i)| {
            p_i.decompose_lsb_bits_at(d_i, mask, bits);
        });
    }
}
