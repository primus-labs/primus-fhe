use primus_factor::{FactorMul, ShoupFactor};
use primus_integer::{BigUint, FheUint};
use primus_reduce::FieldContext;

use crate::RnsError;

use super::{RNSBase, RNSBaseInner};
use std::sync::Arc;

impl<T, M> RNSBase<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Extends the `Q` basis by appending one modulus `p`.
    ///
    /// The new modulus must be coprime with every existing modulus in this
    /// basis.
    ///
    /// This reuses the existing CRT precomputations: each `Q / q_i` is
    /// multiplied by `p`, and its inverse modulo `q_i` is updated with
    /// `p^-1 mod q_i`, avoiding an O(N²) recomputation.
    ///
    /// # Errors
    ///
    /// Returns [`RnsError::NonCoprimeModuli`] when the new modulus is not coprime
    /// with at least one existing modulus.
    pub fn extend(&self, p: M) -> Result<Self, RnsError> {
        let p_val = p.value();

        // Check coprimality between p and every q_i.
        for qi in self.moduli_values().iter().copied() {
            if !p_val.is_coprime(qi) {
                return Err(RnsError::NonCoprimeModuli);
            }
        }

        let qp_moduli_count = self.moduli_count() + 1;
        let mut qp_moduli = self.moduli().to_vec();
        qp_moduli.push(p);

        let BigUint(q) = self.moduli_product();
        let mut qp = BigUint(q.to_vec());
        let carry = qp.mul_value_assign(p_val);

        let qp_punctured_product = if carry.is_zero() {
            let qp_big_uint_len = self.big_uint_value_len();
            let mut qp_punctured_product = vec![T::ZERO; qp_big_uint_len * qp_moduli_count];
            let mut qp_punctured_product_chunks =
                qp_punctured_product.chunks_exact_mut(qp_big_uint_len);

            for (q_div_qi, qp_div_qi) in self
                .iter_punctured_product()
                .zip(&mut qp_punctured_product_chunks)
            {
                let _carry = q_div_qi.mul_value_to(p_val, &mut BigUint(qp_div_qi));
                debug_assert!(_carry.is_zero());
            }

            let qp_div_p = qp_punctured_product_chunks.next().unwrap();
            qp_div_p.copy_from_slice(q);

            qp_punctured_product
        } else {
            qp.0.push(carry);

            let q_big_uint_len = self.big_uint_value_len();
            let qp_big_uint_len = q_big_uint_len + 1;

            let mut qp_punctured_product = vec![T::ZERO; qp_big_uint_len * qp_moduli_count];
            let mut qp_punctured_product_chunks =
                qp_punctured_product.chunks_exact_mut(qp_big_uint_len);

            for (q_div_qi, qp_div_qi) in self
                .iter_punctured_product()
                .zip(&mut qp_punctured_product_chunks)
            {
                let (high_limb, low_limbs) = qp_div_qi.split_last_mut().unwrap();
                *high_limb = q_div_qi.mul_value_to(p_val, &mut BigUint(low_limbs));
            }

            let qp_div_p = qp_punctured_product_chunks.next().unwrap();
            qp_div_p[..q_big_uint_len].copy_from_slice(q);

            qp_punctured_product
        };

        let mut inv_qp_punctured_product_mod_modulus: Vec<ShoupFactor<T>> = self
            .inv_punctured_product_mod_modulus()
            .iter()
            .zip(self.moduli())
            .zip(self.moduli_values().iter().copied())
            .map(|((inv_q_div_qi_mod_qi, &qi), qi_val)| {
                let p_mod_qi = if p_val < qi_val {
                    p_val
                } else {
                    qi.reduce(p_val)
                };
                let inv_p_mod_qi = qi.reduce_inv(p_mod_qi);
                let inv_qp_div_qi_mod_qi =
                    inv_q_div_qi_mod_qi.factor_mul_modulo(inv_p_mod_qi, qi_val);
                ShoupFactor::new(inv_qp_div_qi_mod_qi, qi_val)
            })
            .collect();

        let q_mod_p = p.reduce(q);
        let inv_q_mod_p = p.reduce_inv(q_mod_p);
        inv_qp_punctured_product_mod_modulus.push(ShoupFactor::new(inv_q_mod_p, p_val));

        Ok(Self {
            inner: Arc::new(RNSBaseInner {
                moduli_values: qp_moduli.iter().map(|q| q.value()).collect(),
                moduli: qp_moduli,
                moduli_product: qp,
                punctured_product: qp_punctured_product,
                inv_punctured_product_mod_modulus: inv_qp_punctured_product_mod_modulus,
            }),
        })
    }

    /// Extends the `Q` basis by appending every modulus from `p_base`.
    ///
    /// Every modulus in `p_base` must be coprime with every modulus in `self`.
    ///
    /// # Errors
    ///
    /// Returns [`RnsError::NonCoprimeModuli`] when any modulus in `p_base` is not
    /// coprime with at least one modulus in `self`.
    #[inline]
    pub fn extend_with(&self, p_base: &Self) -> Result<Self, RnsError> {
        let p_moduli_values = p_base.moduli_values();

        for qi in self.moduli_values().iter().copied() {
            for &pi in p_moduli_values {
                if !pi.is_coprime(qi) {
                    return Err(RnsError::NonCoprimeModuli);
                }
            }
        }

        let qp_moduli_count = self.moduli_count() + p_base.moduli_count();
        let mut qp_moduli = self.moduli().to_vec();
        qp_moduli.extend_from_slice(p_base.moduli());

        let BigUint(q) = self.moduli_product();
        let BigUint(p) = p_base.moduli_product();

        let mut qp_added_limb_count = 0;
        let mut qp = BigUint(q.to_vec());
        for &pi in p_moduli_values {
            let carry = qp.mul_value_assign(pi);
            if !carry.is_zero() {
                qp.0.push(carry);
                qp_added_limb_count += 1;
            }
        }

        let q_big_uint_len = self.big_uint_value_len();
        let qp_big_uint_len = q_big_uint_len + qp_added_limb_count;

        let mut qp_punctured_product = vec![T::ZERO; qp_big_uint_len * qp_moduli_count];
        let mut qp_punctured_product_chunks =
            qp_punctured_product.chunks_exact_mut(qp_big_uint_len);

        for (q_div_qi, qp_div_qi) in self
            .iter_punctured_product()
            .zip(&mut qp_punctured_product_chunks)
        {
            // Q/q_i becomes P*(Q/q_i); the final QP width already accommodates
            // every intermediate product, so no limb is discarded here.
            qp_div_qi[..q_big_uint_len].copy_from_slice(q_div_qi.digits());
            let mut qp_div_qi = BigUint(qp_div_qi);
            for &pi in p_moduli_values {
                let _carry = qp_div_qi.mul_value_assign(pi);
                debug_assert!(_carry.is_zero());
            }
        }

        for (pi_index, qp_div_pi) in qp_punctured_product_chunks.enumerate() {
            qp_div_pi[..q_big_uint_len].copy_from_slice(q);
            let qp_div_pi = &mut BigUint(qp_div_pi);
            for (_, &pj) in p_moduli_values
                .iter()
                .enumerate()
                .filter(|(pj_index, _)| pi_index != *pj_index)
            {
                let _carry = qp_div_pi.mul_value_assign(pj);
                debug_assert!(_carry.is_zero());
            }
        }

        // Existing inverses are updated by P^-1 modulo q_i. Only the newly
        // appended moduli require inverses of their full punctured products.
        let mut inv_qp_punctured_product_mod_modulus: Vec<ShoupFactor<T>> = self
            .inv_punctured_product_mod_modulus()
            .iter()
            .zip(self.moduli())
            .zip(self.moduli_values().iter().copied())
            .map(|((inv_q_div_qi_mod_qi, &qi), qi_val)| {
                let p_mod_qi = qi.reduce(p);
                let inv_p_mod_qi = qi.reduce_inv(p_mod_qi);
                let inv_qp_div_qi_mod_qi =
                    inv_q_div_qi_mod_qi.factor_mul_modulo(inv_p_mod_qi, qi_val);
                ShoupFactor::new(inv_qp_div_qi_mod_qi, qi_val)
            })
            .collect();

        for ((qp_div_pi, &pi), &pi_val) in qp_punctured_product
            .chunks_exact(qp_big_uint_len)
            .skip(self.moduli_count())
            .zip(p_base.moduli())
            .zip(p_moduli_values)
        {
            let qp_div_pi_mod_pi = pi.reduce(qp_div_pi);
            let inv_qp_div_pi_mod_pi = pi.reduce_inv(qp_div_pi_mod_pi);
            inv_qp_punctured_product_mod_modulus
                .push(ShoupFactor::new(inv_qp_div_pi_mod_pi, pi_val));
        }

        Ok(Self {
            inner: Arc::new(RNSBaseInner {
                moduli_values: qp_moduli.iter().map(|q| q.value()).collect(),
                moduli: qp_moduli,
                moduli_product: qp,
                punctured_product: qp_punctured_product,
                inv_punctured_product_mod_modulus: inv_qp_punctured_product_mod_modulus,
            }),
        })
    }
}
