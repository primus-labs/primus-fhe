use core::cmp::Ordering;

use primus_data::{Data, DataMut};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64DcrtTable};
use primus_reduce::{ReduceAdd, ReduceMul};
use primus_rns::{HpsRns, HpsRnsWorkspace, RNSBase};

use crate::{BfvCiphertext, BfvContext, BfvMultiplyError, BfvQuadraticCiphertext};

use super::{cmp_words, gcd, is_prime, mul_scalar_to};

/// One-sided HPS P/Q scaling followed by exact RNS t/P scale-and-round.
///
/// This owner is used only by ordinary BFV multiplication. It cannot be used as
/// an unscaled tensor owner, in particular by mixed BFV/BGV lookup arithmetic.
/// The P-basis scaled input uses HPS's sum-of-fractions rounding, not a claim
/// that approximate basis conversion is exact lifting. Centered basis
/// expansion and the final nearest rounding are exact, including boundaries.
///
/// If L is the Q prime count, a centered input coefficient x is pre-scaled to
/// y=P*x/Q+epsilon-P*kappa with 0<=epsilon<L. P>2L makes kappa in {0,1}.
/// Rounding and the two-component phase residual must be budgeted by callers;
/// choosing a computation basis does not establish a ciphertext noise bound.
pub(crate) struct HpsMultiplier<'a> {
    context: &'a BfvContext,
    level: usize,
    rns: HpsRns,
    table_p: U64DcrtTable,
    workspace: HpsRnsWorkspace,
    coefficients: Vec<u64>,
    lhs_p: Vec<u64>,
    rhs_qp: Vec<u64>,
    tensor: Vec<u64>,
}

impl<'a> HpsMultiplier<'a> {
    pub(crate) fn try_with_default_basis(
        context: &'a BfvContext,
        level: usize,
    ) -> Result<Self, BfvMultiplyError> {
        check_level(context, level)?;
        let primes = default_auxiliary_moduli(context, level)?;
        Self::try_new(context, level, &primes)
    }

    pub(crate) fn try_new(
        context: &'a BfvContext,
        level: usize,
        auxiliary_moduli: &[u64],
    ) -> Result<Self, BfvMultiplyError> {
        check_level(context, level)?;
        let n = context.parameters().poly_length().get();
        let base_q = context.codec(level).base_q();
        let two_n = n.checked_mul(2).ok_or(BfvMultiplyError::LengthOverflow)?;
        for (index, &p) in auxiliary_moduli.iter().enumerate() {
            if !(3..(1 << 62)).contains(&p) || p % two_n as u64 != 1 {
                return Err(BfvMultiplyError::AuxiliaryModulus { index, modulus: p });
            }
            for &q in base_q.moduli_values() {
                if gcd(p, q) != 1 {
                    return Err(BfvMultiplyError::NonCoprime {
                        auxiliary: p,
                        ciphertext: q,
                    });
                }
            }
        }
        let moduli_p: Vec<_> = auxiliary_moduli
            .iter()
            .copied()
            .map(BarrettModulus::new)
            .collect();
        let base_p = RNSBase::new(&moduli_p)?;
        let minimum_p = base_q
            .moduli_count()
            .checked_mul(2)
            .and_then(|x| u64::try_from(x).ok())
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        if cmp_words(base_p.moduli_product().digits(), &[minimum_p]) != Ordering::Greater {
            return Err(BfvMultiplyError::InsufficientHpsAuxiliaryProduct);
        }
        let q_length = context.rns_poly_len(level);
        let p_length = n
            .checked_mul(base_p.moduli_count())
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let combined_length = q_length
            .checked_add(p_length)
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let q_inputs = q_length
            .checked_mul(2)
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let p_inputs = p_length
            .checked_mul(2)
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let qp_inputs = combined_length
            .checked_mul(2)
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let tensor_length = combined_length
            .checked_mul(3)
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let table_p = U64DcrtTable::new(context.parameters().poly_length(), base_p.moduli())?;
        let rns = HpsRns::try_new(base_q, &base_p, context.codec(level).t())?;
        let workspace = rns.workspace(n);
        Ok(Self {
            context,
            level,
            rns,
            table_p,
            workspace,
            coefficients: vec![0; q_inputs],
            lhs_p: vec![0; p_inputs],
            rhs_qp: vec![0; qp_inputs],
            tensor: vec![0; tensor_length],
        })
    }

    pub(crate) fn auxiliary_moduli(&self) -> &[u64] {
        self.rns.base_p().moduli_values()
    }

    pub(crate) fn multiply_to<A, B, C>(
        &mut self,
        lhs: &BfvCiphertext<A>,
        rhs: &BfvCiphertext<B>,
        output: &mut BfvQuadraticCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        lhs.check_binding(self.context, self.level);
        rhs.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let q_length = self.context.rns_poly_len(self.level);
        assert_eq!(lhs.as_ref().len(), 2 * q_length);
        assert_eq!(rhs.as_ref().len(), 2 * q_length);
        assert_eq!(output.as_ref().len(), 3 * q_length);
        self.inverse_q_coefficients(lhs.as_ref());
        self.prepare_lhs_coefficients();
        self.inverse_q_coefficients(rhs.as_ref());
        self.prepare_rhs_coefficients();
        self.tensor(lhs.as_ref());
        self.scale(output.as_mut());
    }

    pub(crate) fn square_to<A, C>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut BfvQuadraticCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        input.check_binding(self.context, self.level);
        output.check_binding(self.context, self.level);
        let q_length = self.context.rns_poly_len(self.level);
        assert_eq!(input.as_ref().len(), 2 * q_length);
        assert_eq!(output.as_ref().len(), 3 * q_length);
        // HPSPOVERQ still needs both asymmetric lifts: the right copy is
        // pre-scaled and the left is only expanded. Their shared coefficient
        // input is read-only, so one copy/INTT serves both without identifying
        // their distinct scaling residuals or using exact square's products.
        self.inverse_q_coefficients(input.as_ref());
        self.prepare_lhs_coefficients();
        self.prepare_rhs_coefficients();
        self.tensor(input.as_ref());
        self.scale(output.as_mut());
    }

    fn inverse_q_coefficients(&mut self, input: &[u64]) {
        self.coefficients.copy_from_slice(input);
        let n = self.context.parameters().poly_length().get();
        let q_length = self.context.rns_poly_len(self.level);
        for component in self.coefficients.chunks_exact_mut(q_length) {
            for (table, values) in self
                .context
                .table()
                .iter()
                .zip(component.chunks_exact_mut(n))
            {
                table.inverse_transform_slice(values);
            }
        }
    }

    fn prepare_lhs_coefficients(&mut self) {
        let n = self.context.parameters().poly_length().get();
        let q_length = self.context.rns_poly_len(self.level);
        let p_length = self.table_p.rns_poly_len();
        for (coefficients, lifted) in self
            .coefficients
            .chunks_exact(q_length)
            .zip(self.lhs_p.chunks_exact_mut(p_length))
        {
            self.rns
                .expand_q_to_p(coefficients, lifted, n, &mut self.workspace);
            self.table_p.transform_slice(lifted);
        }
    }

    fn prepare_rhs_coefficients(&mut self) {
        let n = self.context.parameters().poly_length().get();
        let q_length = self.context.rns_poly_len(self.level);
        let combined_length = q_length + self.table_p.rns_poly_len();
        for (coefficients, scaled) in self
            .coefficients
            .chunks_exact(q_length)
            .zip(self.rhs_qp.chunks_exact_mut(combined_length))
        {
            let (scaled_q, scaled_p) = scaled.split_at_mut(q_length);
            self.rns
                .scale_q_to_p(coefficients, scaled_p, n, &mut self.workspace);
            self.rns
                .expand_p_to_q(scaled_p, scaled_q, n, &mut self.workspace);
            for (table, values) in self
                .context
                .table()
                .iter()
                .zip(scaled_q.chunks_exact_mut(n))
            {
                table.transform_slice(values);
            }
            self.table_p.transform_slice(scaled_p);
        }
    }

    fn tensor(&mut self, lhs_q: &[u64]) {
        let n = self.context.parameters().poly_length().get();
        let base_q = self.context.codec(self.level).base_q();
        let q_length = self.context.rns_poly_len(self.level);
        let p_length = self.table_p.rns_poly_len();
        let combined_length = q_length + p_length;
        let (out0, rest) = self.tensor.split_at_mut(combined_length);
        let (out1, out2) = rest.split_at_mut(combined_length);
        for (index, &modulus) in base_q
            .moduli()
            .iter()
            .chain(self.rns.base_p().moduli())
            .enumerate()
        {
            let (lhs, offset, lhs_component_length) = if index < base_q.moduli_count() {
                (lhs_q, index * n, q_length)
            } else {
                (
                    self.lhs_p.as_slice(),
                    (index - base_q.moduli_count()) * n,
                    p_length,
                )
            };
            let destination = index * n;
            for j in 0..n {
                let a0 = lhs[offset + j];
                let a1 = lhs[lhs_component_length + offset + j];
                let b0 = self.rhs_qp[destination + j];
                let b1 = self.rhs_qp[combined_length + destination + j];
                out0[destination + j] = modulus.reduce_mul(a0, b0);
                out1[destination + j] =
                    modulus.reduce_add(modulus.reduce_mul(a0, b1), modulus.reduce_mul(a1, b0));
                out2[destination + j] = modulus.reduce_mul(a1, b1);
            }
        }
    }

    fn scale(&mut self, output: &mut [u64]) {
        let n = self.context.parameters().poly_length().get();
        let q_length = self.context.rns_poly_len(self.level);
        let q_count = self.context.codec(self.level).base_q().moduli_count();
        let combined_length = q_length + self.table_p.rns_poly_len();
        for (tensor, scaled) in self
            .tensor
            .chunks_exact_mut(combined_length)
            .zip(output.chunks_exact_mut(q_length))
        {
            for (table, values) in self
                .context
                .table()
                .iter()
                .take(q_count)
                .chain(self.table_p.iter())
                .zip(tensor.chunks_exact_mut(n))
            {
                table.inverse_transform_slice(values);
            }
            let (tensor_q, tensor_p) = tensor.split_at(q_length);
            self.rns
                .scale_and_round(tensor_q, tensor_p, scaled, n, &mut self.workspace);
            for (table, values) in self.context.table().iter().zip(scaled.chunks_exact_mut(n)) {
                table.transform_slice(values);
            }
        }
    }
}

fn check_level(context: &BfvContext, level: usize) -> Result<(), BfvMultiplyError> {
    if level >= context.level_count() {
        Err(BfvMultiplyError::Level {
            requested: level,
            maximum: context.level_count(),
        })
    } else {
        Ok(())
    }
}

// This arithmetic policy reserves Q/(8t) for the bounded epsilon term using
// H=||s||_1<=N*B for the configured sampler support B. It does not certify
// input noise, the wrap term, relinearization,
// plaintext growth or depth. Explicit bases can use another validated budget.
fn default_auxiliary_moduli(
    context: &BfvContext,
    level: usize,
) -> Result<Vec<u64>, BfvMultiplyError> {
    let n = u64::try_from(context.parameters().poly_length().get())
        .map_err(|_| BfvMultiplyError::LengthOverflow)?;
    let step = n
        .checked_mul(2)
        .filter(|&x| x < (1 << 60))
        .ok_or(BfvMultiplyError::LengthOverflow)?;
    let support = context
        .parameters()
        .encryption_parameters()
        .secret_key_sampler()
        .maximum_magnitude();
    let h_plus_one = n
        .checked_mul(support)
        .and_then(|h| h.checked_add(1))
        .ok_or(BfvMultiplyError::LengthOverflow)?;
    let base_q = context.codec(level).base_q();
    let count =
        u64::try_from(base_q.moduli_count()).map_err(|_| BfvMultiplyError::LengthOverflow)?;
    // K=4*t^2*N*L*(1+N*B)^2, calculated in exact setup words.
    let mut target = vec![4];
    let t = context.codec(level).t();
    for scalar in [t, t, n, count, h_plus_one, h_plus_one] {
        let mut next = vec![0; target.len() + 1];
        mul_scalar_to(&target, scalar, &mut next);
        target = next;
    }
    let mut candidate = ((1u64 << 60) - 2) / step * step + 1;
    let mut product = vec![1];
    let mut primes = Vec::new();
    while cmp_words(&product, &target) == Ordering::Less {
        while candidate > (1 << 59)
            && (!is_prime(candidate)
                || base_q
                    .moduli_values()
                    .iter()
                    .any(|&q| gcd(candidate, q) != 1))
        {
            candidate = candidate.saturating_sub(step);
        }
        if candidate <= (1 << 59) {
            return Err(BfvMultiplyError::AuxiliarySearchExhausted);
        }
        primes.push(candidate);
        let mut next = vec![0; product.len() + 1];
        mul_scalar_to(&product, candidate, &mut next);
        product = next;
        candidate = candidate.saturating_sub(step);
    }
    Ok(primes)
}

#[cfg(test)]
mod tests;
