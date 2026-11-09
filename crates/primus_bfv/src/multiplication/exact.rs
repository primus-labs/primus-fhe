//! Exact tensoring over the centered integer lifts, followed by scale-and-round.

mod rounding;

#[cfg(test)]
mod reference;

use core::cmp::Ordering;

use primus_data::{Data, DataMut};
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64DcrtTable};
use primus_reduce::{Reduce, ReduceAdd, ReduceInv, ReduceMul, ReduceSub};
use primus_rns::{RNSBase, Residues};

use crate::{BfvCiphertext, BfvContext, advanced::BfvQuadraticCiphertext};

use self::rounding::ScalarQuotient;
use super::{
    BfvMultiplyError,
    auxiliary::{check_level, prepare_auxiliary_base, search_auxiliary_moduli},
    check_ciphertext,
    words::{cmp_words, half, mul_scalar_to},
};

/// Prepared exact RNS/NTT BFV multiplication at one ciphertext level.
///
/// Auxiliary P is computation-only: it never changes the encryption parameters
/// or secret. The input components are lifted from their centered Q coefficient
/// representatives, tensoring is performed in QP with NTTs, and each complete
/// integer tensor coefficient z is scaled as `round(t*z/Q) mod Q`. The two
/// cross products are added before rounding. No floating-point approximation or
/// auxiliary decoder is used. All online methods allocate nothing.
///
/// # Correctness
/// Inputs must be canonical NTT ciphertexts in the bound ordered Q basis, with
/// the same actual secret and NTT convention. Numeric metadata does not prove
/// those identities. Q and P must contain actual NTT primes; table construction
/// does not certify primality. The resulting degree-two ciphertext must be
/// relinearized before degree-one operations; its full evaluated noise must
/// remain recoverable independently of the fresh encryption bound.
pub struct BfvMultiplier<'a> {
    context: &'a BfvContext,
    level: usize,
    lift: LiftParameters,
    workspace: MultiplyWorkspace,
    raw: Vec<u64>,
}

struct LiftParameters {
    base_p: RNSBase<u64, BarrettModulus<u64>>,
    table_p: U64DcrtTable,
    half_q: Vec<u64>,
    half_p: Vec<u64>,
    q_mod_p: Vec<u64>,
    inv_q_mod_p: Vec<u64>,
    p_mod_q: Vec<u64>,
}

struct MultiplyWorkspace {
    // Each input is lifted into P before the next input overwrites these coefficients.
    coefficients: Vec<u64>,
    lhs_p: Vec<u64>,
    rhs_p: Vec<u64>,
    residues: Vec<u64>,
    value_q: Vec<u64>,
    value_p: Vec<u64>,
    rounder: ScalarQuotient,
}

impl<'a> BfvMultiplier<'a> {
    /// Prepares computation-only 60-bit NTT primes automatically.
    ///
    /// Chooses distinct primes coprime to Q until their exact product exceeds
    /// NQ. Prime search and all tables/scratch are prepared here, never online.
    /// This selects arithmetic resources, not encryption or security parameters.
    /// Use [`Self::try_new`] for an explicitly chosen computation basis.
    ///
    /// # Errors
    /// Rejects an unprepared level, overflowing geometry, exhausted search range
    /// or unsupported transform parameters.
    pub fn try_with_default_basis(
        context: &'a BfvContext,
        level: usize,
    ) -> Result<Self, BfvMultiplyError> {
        check_level(context, level)?;
        Self::prepare(context, level, None)
    }

    /// Prepares an explicit computation basis whose product P is greater than NQ.
    ///
    /// The auxiliary basis is pairwise coprime and coprime to Q. Its primes must
    /// support this ring's NTT and satisfy the optimized u64 table's range. The
    /// product check uses exact multiword integers; neither Q nor P is narrowed.
    ///
    /// # Errors
    /// Rejects an unprepared level, invalid or noncoprime auxiliary moduli,
    /// insufficient P, unsupported NTT or overflowing complete storage length.
    pub fn try_new(
        context: &'a BfvContext,
        level: usize,
        auxiliary_moduli: &[u64],
    ) -> Result<Self, BfvMultiplyError> {
        check_level(context, level)?;
        Self::prepare(context, level, Some(auxiliary_moduli))
    }

    // The public constructor or the prepared relinearizer validated level.
    pub(super) fn prepare(
        context: &'a BfvContext,
        level: usize,
        auxiliary_moduli: Option<&[u64]>,
    ) -> Result<Self, BfvMultiplyError> {
        let n = context.parameters().poly_length().get();
        let base_q = context.codec(level).base_q();
        let mut n_q = vec![0; base_q.big_uint_value_len() + 1];
        mul_scalar_to(base_q.moduli_product().digits(), n as u64, &mut n_q);
        let default_moduli;
        let auxiliary_moduli = match auxiliary_moduli {
            Some(moduli) => moduli,
            None => {
                default_moduli = search_auxiliary_moduli(n, base_q.moduli_values(), &n_q)?;
                &default_moduli
            }
        };
        let base_p = prepare_auxiliary_base(n, base_q, auxiliary_moduli)?;
        if cmp_words(base_p.moduli_product().digits(), &n_q) != Ordering::Greater {
            return Err(BfvMultiplyError::InsufficientAuxiliaryProduct);
        }
        let raw_length = base_q
            .moduli_count()
            .checked_add(base_p.moduli_count())
            .and_then(|count| count.checked_mul(n))
            .and_then(|length| length.checked_mul(3))
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let q_length = context.rns_poly_len(level);
        let p_length = n
            .checked_mul(base_p.moduli_count())
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let q_input_length = q_length
            .checked_mul(2)
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let p_input_length = p_length
            .checked_mul(2)
            .ok_or(BfvMultiplyError::LengthOverflow)?;
        let table_p = U64DcrtTable::new(context.parameters().poly_length(), base_p.moduli())?;
        let q_mod_p = base_p.decompose(base_q.moduli_product()).0;
        let inv_q_mod_p = base_p
            .moduli()
            .iter()
            .zip(&q_mod_p)
            .map(|(p, &q)| p.reduce_inv(q))
            .collect();
        let p_mod_q = base_q.decompose(base_p.moduli_product()).0;
        let workspace = MultiplyWorkspace {
            coefficients: vec![0; q_input_length],
            lhs_p: vec![0; p_input_length],
            rhs_p: vec![0; p_input_length],
            residues: vec![0; base_q.moduli_count().max(base_p.moduli_count())],
            value_q: vec![0; base_q.big_uint_value_len()],
            value_p: vec![0; base_p.big_uint_value_len()],
            rounder: ScalarQuotient::new(base_q.moduli_product().digits()),
        };
        let lift = LiftParameters {
            half_q: half(base_q.moduli_product().digits()),
            half_p: half(base_p.moduli_product().digits()),
            base_p,
            table_p,
            q_mod_p,
            inv_q_mod_p,
            p_mod_q,
        };
        Ok(Self {
            context,
            level,
            lift,
            workspace,
            raw: vec![0; raw_length],
        })
    }

    /// Borrows the computation-only ordered auxiliary moduli.
    #[must_use]
    pub fn auxiliary_moduli(&self) -> &[u64] {
        self.lift.base_p.moduli_values()
    }

    /// Writes the scaled degree-two product, using prepared internal raw storage.
    ///
    /// # Panics
    /// Rejects recorded context/level conflicts and incorrect complete lengths
    /// before any writes. Inherits
    /// the centered integer lift and exact scaling contracts described above.
    pub fn multiply_to<A, B, C>(
        &mut self,
        lhs: &BfvCiphertext<A>,
        rhs: &BfvCiphertext<B>,
        output: &mut BfvQuadraticCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        B: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        check_ciphertext(self.context, self.level, lhs);
        check_ciphertext(self.context, self.level, rhs);
        self.check_output(output);
        self.multiply_scaled_to(lhs.as_ref(), rhs.as_ref(), output.as_mut());
    }

    /// Writes the scaled square with a single lifted input and three NTT products.
    ///
    /// Inherits [`Self::multiply_to`]'s math and prewrite checks.
    pub fn square_to<A, C>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut BfvQuadraticCiphertext<C>,
    ) where
        A: Data<Elem = u64>,
        C: DataMut<Elem = u64>,
    {
        check_ciphertext(self.context, self.level, input);
        self.check_output(output);
        self.square_scaled_to(input.as_ref(), output.as_mut());
    }

    fn check_output<C: Data<Elem = u64>>(&self, output: &BfvQuadraticCiphertext<C>) {
        output.check_binding(self.context, self.level);
        assert_eq!(
            output.as_ref().len(),
            3 * self.context.rns_poly_len(self.level)
        );
    }

    // Caller has checked both input lengths/bindings and supplied the complete
    // scaled tensor output at this level, or owns the matching internal scratch.
    pub(super) fn multiply_scaled_to(&mut self, lhs: &[u64], rhs: &[u64], output: &mut [u64]) {
        self.scaled_tensor_to(lhs, rhs, false, output);
    }

    // Same preconditions as multiply_scaled_to, with one input used twice.
    pub(super) fn square_scaled_to(&mut self, input: &[u64], output: &mut [u64]) {
        self.scaled_tensor_to(input, input, true, output);
    }

    fn scaled_tensor_to(&mut self, lhs: &[u64], rhs: &[u64], square: bool, output: &mut [u64]) {
        self.workspace.tensor(
            self.context,
            self.level,
            &self.lift,
            lhs,
            rhs,
            square,
            &mut self.raw,
        );
        self.workspace
            .scale(self.context, self.level, &self.lift, &mut self.raw, output);
    }
}

impl MultiplyWorkspace {
    #[allow(clippy::too_many_arguments)] // One complete tensor kernel and its validated layout.
    fn tensor(
        &mut self,
        context: &BfvContext,
        level: usize,
        lift: &LiftParameters,
        lhs: &[u64],
        rhs: &[u64],
        square: bool,
        output: &mut [u64],
    ) {
        prepare_lift(
            context,
            level,
            lift,
            lhs,
            &mut self.coefficients,
            &mut self.lhs_p,
            &mut self.residues,
            &mut self.value_q,
        );
        if !square {
            prepare_lift(
                context,
                level,
                lift,
                rhs,
                &mut self.coefficients,
                &mut self.rhs_p,
                &mut self.residues,
                &mut self.value_q,
            );
        }
        let n = context.parameters().poly_length().get();
        let q_length = context.rns_poly_len(level);
        let p_length = lift.table_p.rns_poly_len();
        let combined_length = q_length + p_length;
        let (out0, rest) = output.split_at_mut(combined_length);
        let (out1, out2) = rest.split_at_mut(combined_length);
        for (index, &modulus) in context
            .codec(level)
            .base_q()
            .moduli()
            .iter()
            .chain(lift.base_p.moduli())
            .enumerate()
        {
            let (a, b, offset, component_length) = if index < q_length / n {
                (lhs, rhs, index * n, q_length)
            } else {
                (
                    self.lhs_p.as_slice(),
                    if square {
                        self.lhs_p.as_slice()
                    } else {
                        self.rhs_p.as_slice()
                    },
                    (index - q_length / n) * n,
                    p_length,
                )
            };
            let destination = index * n;
            for j in 0..n {
                let a0 = a[offset + j];
                let a1 = a[component_length + offset + j];
                let b0 = b[offset + j];
                let b1 = b[component_length + offset + j];
                out0[destination + j] = modulus.reduce_mul(a0, b0);
                out1[destination + j] = if square {
                    let product = modulus.reduce_mul(a0, a1);
                    modulus.reduce_add(product, product)
                } else {
                    modulus.reduce_add(modulus.reduce_mul(a0, b1), modulus.reduce_mul(a1, b0))
                };
                out2[destination + j] = modulus.reduce_mul(a1, b1);
            }
        }
    }

    fn scale(
        &mut self,
        context: &BfvContext,
        level: usize,
        lift: &LiftParameters,
        input: &mut [u64],
        output: &mut [u64],
    ) {
        let n = context.parameters().poly_length().get();
        let base_q = context.codec(level).base_q();
        let t = context.codec(level).t();
        let q_count = base_q.moduli_count();
        let p_count = lift.base_p.moduli_count();
        let q_length = n * q_count;
        let combined_length = n * (q_count + p_count);
        // The completed tensor is consumed here: no later stage needs its NTT
        // form. Transform in place instead of retaining a second QP tensor.
        for component in input.chunks_exact_mut(combined_length) {
            for (table, values) in context
                .table()
                .iter()
                .take(q_count)
                .chain(lift.table_p.iter())
                .zip(component.chunks_exact_mut(n))
            {
                table.inverse_transform_slice(values);
            }
        }
        for (raw, scaled) in input
            .chunks_exact(combined_length)
            .zip(output.chunks_exact_mut(q_length))
        {
            for coefficient in 0..n {
                for (i, residue) in self.residues[..q_count].iter_mut().enumerate() {
                    *residue = raw[i * n + coefficient];
                }
                base_q.compose_to(
                    Residues(&self.residues[..q_count]),
                    BigUint(self.value_q.as_mut_slice()),
                );
                let rounded = self.rounder.round(&self.value_q, t, &lift.half_q);
                // z = Q*k+r, with canonical 0<=r<Q. P>NQ distinguishes the
                // signed k even for the sum of the two middle tensor products.
                for (i, ((p, &inverse), residue)) in lift
                    .base_p
                    .moduli()
                    .iter()
                    .zip(&lift.inv_q_mod_p)
                    .zip(&mut self.residues[..p_count])
                    .enumerate()
                {
                    let r = p.reduce(self.value_q.as_slice());
                    let z = raw[q_length + i * n + coefficient];
                    *residue = p.reduce_mul(p.reduce_sub(z, r), inverse);
                }
                lift.base_p.compose_to(
                    Residues(&self.residues[..p_count]),
                    BigUint(self.value_p.as_mut_slice()),
                );
                let negative = cmp_words(&self.value_p, &lift.half_p) == Ordering::Greater;
                for (i, (&q, &p_mod_q)) in base_q.moduli().iter().zip(&lift.p_mod_q).enumerate() {
                    let mut quotient = q.reduce(self.value_p.as_slice());
                    if negative {
                        quotient = q.reduce_sub(quotient, p_mod_q);
                    }
                    scaled[i * n + coefficient] =
                        q.reduce_add(q.reduce_mul(quotient, q.reduce(t)), q.reduce(rounded));
                }
            }
            for (table, values) in context
                .table()
                .iter()
                .take(q_count)
                .zip(scaled.chunks_exact_mut(n))
            {
                table.transform_slice(values);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)] // Disjoint prepared buffers avoid a second owner or copying.
fn prepare_lift(
    context: &BfvContext,
    level: usize,
    lift: &LiftParameters,
    input: &[u64],
    coefficients: &mut [u64],
    lifted: &mut [u64],
    residues: &mut [u64],
    value: &mut [u64],
) {
    let n = context.parameters().poly_length().get();
    let base_q = context.codec(level).base_q();
    let q_count = base_q.moduli_count();
    let q_length = q_count * n;
    let p_length = lift.table_p.rns_poly_len();
    coefficients.copy_from_slice(input);
    for component in coefficients.chunks_exact_mut(q_length) {
        for (table, values) in context
            .table()
            .iter()
            .take(q_count)
            .zip(component.chunks_exact_mut(n))
        {
            table.inverse_transform_slice(values);
        }
    }
    for (component, output) in coefficients
        .chunks_exact(q_length)
        .zip(lifted.chunks_exact_mut(p_length))
    {
        for coefficient in 0..n {
            for (i, residue) in residues[..q_count].iter_mut().enumerate() {
                *residue = component[i * n + coefficient];
            }
            base_q.compose_to(Residues(&residues[..q_count]), BigUint(&mut *value));
            let negative = cmp_words(value, &lift.half_q) == Ordering::Greater;
            for (i, (&p, &q_mod_p)) in lift.base_p.moduli().iter().zip(&lift.q_mod_p).enumerate() {
                let residue = p.reduce(&*value);
                output[i * n + coefficient] = if negative {
                    p.reduce_sub(residue, q_mod_p)
                } else {
                    residue
                };
            }
        }
        lift.table_p.transform_slice(output);
    }
}

#[cfg(test)]
mod tests_tensor;
