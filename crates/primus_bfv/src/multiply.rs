pub(crate) mod hps;

#[cfg(test)]
mod reference;

use core::cmp::Ordering;

use primus_data::{Data, DataMut};
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttError, NttTable, U64DcrtTable};
use primus_reduce::{Reduce, ReduceAdd, ReduceInv, ReduceMul, ReduceSub};
use primus_rns::{RNSBase, Residues, RnsError};

use crate::{BfvCiphertext, BfvContext, BfvQuadraticCiphertext};

/// Invalid level or computation-only basis for ordinary BFV multiplication.
#[derive(Debug, thiserror::Error)]
pub enum BfvMultiplyError {
    /// The requested ciphertext level was not prepared.
    #[error("BFV multiplication level {requested} is outside 0..{maximum}")]
    Level {
        /// Requested level.
        requested: usize,
        /// Number of prepared levels.
        maximum: usize,
    },
    /// Auxiliary moduli must be odd, below 2^62 and support a 2N-th root.
    #[error("invalid BFV multiplication auxiliary modulus {modulus} at index {index}")]
    AuxiliaryModulus {
        /// Position in the auxiliary basis.
        index: usize,
        /// Supplied modulus.
        modulus: u64,
    },
    /// An auxiliary modulus is not coprime to the ciphertext basis.
    #[error("BFV multiplication auxiliary modulus {auxiliary} is not coprime to {ciphertext}")]
    NonCoprime {
        /// Auxiliary modulus.
        auxiliary: u64,
        /// Ciphertext modulus.
        ciphertext: u64,
    },
    /// The auxiliary product must be strictly greater than NQ.
    #[error("BFV multiplication auxiliary product must be greater than NQ")]
    InsufficientAuxiliaryProduct,
    /// HPS's auxiliary product must exceed twice the ciphertext-prime count.
    #[error("BFV HPS multiplication auxiliary product must exceed twice the Q prime count")]
    InsufficientHpsAuxiliaryProduct,
    /// No further NTT primes were found in the automatic 60-bit search range.
    #[error("BFV multiplication could not prepare a sufficient automatic auxiliary basis")]
    AuxiliarySearchExhausted,
    /// An evaluation key is incompatible with the requested computation.
    #[error(transparent)]
    EvaluationKey(#[from] crate::BfvEvaluationKeyError),
    /// A complete prepared storage length is not representable.
    #[error("BFV multiplication workspace length overflow")]
    LengthOverflow,
    /// Invalid auxiliary RNS basis.
    #[error(transparent)]
    Rns(#[from] RnsError),
    /// Invalid auxiliary NTT parameters.
    #[error(transparent)]
    Transform(#[from] NttError<u64>),
}

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
        if level >= context.level_count() {
            return Err(BfvMultiplyError::Level {
                requested: level,
                maximum: context.level_count(),
            });
        }
        let primes = default_auxiliary_moduli(context, level)?;
        Self::try_new(context, level, &primes)
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
        if level >= context.level_count() {
            return Err(BfvMultiplyError::Level {
                requested: level,
                maximum: context.level_count(),
            });
        }
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
        let moduli_p = auxiliary_moduli
            .iter()
            .map(|&p| BarrettModulus::new(p))
            .collect::<Vec<_>>();
        let base_p = RNSBase::new(&moduli_p)?;
        let mut n_q = vec![0; base_q.big_uint_value_len() + 1];
        mul_scalar_to(base_q.moduli_product().digits(), n as u64, &mut n_q);
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

    /// Returns the bound ciphertext level.
    #[must_use]
    pub fn level(&self) -> usize {
        self.level
    }

    /// Borrows the computation-only ordered auxiliary moduli.
    #[must_use]
    pub fn auxiliary_moduli(&self) -> &[u64] {
        self.lift.base_p.moduli_values()
    }

    /// Writes the scaled degree-two product, using prepared internal raw storage.
    ///
    /// # Panics
    /// Rejects every complete input/output length before any writes. Inherits
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
        self.validate_input(lhs.as_ref());
        self.validate_input(rhs.as_ref());
        self.validate_output(output.as_ref());
        self.workspace.tensor(
            self.context,
            self.level,
            &self.lift,
            lhs.as_ref(),
            rhs.as_ref(),
            false,
            &mut self.raw,
        );
        self.workspace.scale(
            self.context,
            self.level,
            &self.lift,
            &mut self.raw,
            output.as_mut(),
        );
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
        self.validate_input(input.as_ref());
        self.validate_output(output.as_ref());
        self.workspace.tensor(
            self.context,
            self.level,
            &self.lift,
            input.as_ref(),
            input.as_ref(),
            true,
            &mut self.raw,
        );
        self.workspace.scale(
            self.context,
            self.level,
            &self.lift,
            &mut self.raw,
            output.as_mut(),
        );
    }

    fn validate_input(&self, input: &[u64]) {
        assert_eq!(input.len(), 2 * self.context.rns_poly_len(self.level));
    }

    fn validate_output(&self, output: &[u64]) {
        assert_eq!(output.len(), 3 * self.context.rns_poly_len(self.level));
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

// The exact quotient floor((t*r+floor(Q/2))/Q) fits in one u64 because
// 0<=r<Q and t<2^63. After normalizing Q's high limb, division by its high
// word overestimates the quotient by at most two. If B=2^64, normalized
// Q=v*B^(l-1)+low with v>=B/2. For the true h, W<(h+1)*Q, so the top-word
// estimate is <h+1+(h+1)/v<=h+3. It is >=h because the truncated denominator
// is <=Q. The codec checks t<gamma<=u64::MAX/2, hence h<=t<2^63 and h+2
// still fits u64. Full integer comparisons remove the overestimate; there is
// no precision or probabilistic fallback.
struct ScalarQuotient {
    normalized_q: Vec<u64>,
    shift: u32,
    numerator: Vec<u64>,
    product: Vec<u64>,
}

impl ScalarQuotient {
    fn new(q: &[u64]) -> Self {
        let live = q.iter().rposition(|&x| x != 0).expect("nonzero Q") + 1;
        let mut normalized_q = q[..live].to_vec();
        let shift = normalized_q[live - 1].leading_zeros();
        let carry = shift_left(&mut normalized_q, shift);
        debug_assert_eq!(carry, 0);
        Self {
            normalized_q,
            shift,
            numerator: vec![0; live + 1],
            product: vec![0; live + 1],
        }
    }

    fn round(&mut self, r: &[u64], t: u64, half_q: &[u64]) -> u64 {
        let length = self.normalized_q.len();
        mul_scalar_to(&r[..length], t, &mut self.numerator);
        add_words_assign(&mut self.numerator, half_q);
        let carry = shift_left(&mut self.numerator, self.shift);
        debug_assert_eq!(carry, 0);
        let leading = ((self.numerator[length] as u128) << 64) | self.numerator[length - 1] as u128;
        let estimate = leading / self.normalized_q[length - 1] as u128;
        let mut quotient = u64::try_from(estimate).expect("BFV scale quotient fits u64");
        mul_scalar_to(&self.normalized_q, quotient, &mut self.product);
        let mut corrections = 0;
        while cmp_words(&self.product, &self.numerator) == Ordering::Greater {
            quotient -= 1;
            sub_words_assign(&mut self.product, &self.normalized_q);
            corrections += 1;
        }
        debug_assert!(corrections <= 2);
        quotient
    }
}

// This is arithmetic preparation, not parameter/security selection. Search
// downward in the 60-bit NTT progression, keeping the exact product in words.
// One owner chooses P; the normal explicit constructor validates/prepares it.
fn default_auxiliary_moduli(
    context: &BfvContext,
    level: usize,
) -> Result<Vec<u64>, BfvMultiplyError> {
    let n = context.parameters().poly_length().get();
    let step = u64::try_from(n)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .filter(|&step| step < (1 << 60))
        .ok_or(BfvMultiplyError::LengthOverflow)?;
    let base = context.codec(level).base_q();
    let mut target = vec![0; base.big_uint_value_len() + 1];
    mul_scalar_to(base.moduli_product().digits(), n as u64, &mut target);
    let mut product = vec![1];
    let mut primes = Vec::new();
    let mut candidate = ((1u64 << 60) - 2) / step * step + 1;
    while cmp_words(&product, &target) != Ordering::Greater {
        while candidate > (1 << 59)
            && (!is_prime(candidate)
                || base.moduli_values().iter().any(|&q| gcd(candidate, q) != 1))
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

// Deterministic Miller-Rabin for u64; modular products fit u128. These seven
// bases cover n<2^64 (also used in SymPy's deterministic isprime branch):
// https://github.com/sympy/sympy/blob/master/sympy/ntheory/primetest.py
// This helper is private to setup; no new public number-theory API is needed.
pub(crate) fn is_prime(n: u64) -> bool {
    if n < 2 || n.is_multiple_of(2) {
        return n == 2;
    }
    let powers = (n - 1).trailing_zeros();
    let odd = (n - 1) >> powers;
    for base in [2u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        let mut base = base % n;
        if base == 0 {
            continue;
        }
        let mut exponent = odd;
        let mut value = 1u64;
        while exponent != 0 {
            if exponent & 1 != 0 {
                value = (value as u128 * base as u128 % n as u128) as u64;
            }
            base = (base as u128 * base as u128 % n as u128) as u64;
            exponent >>= 1;
        }
        if value == 1 || value == n - 1 {
            continue;
        }
        let mut passed = false;
        for _ in 1..powers {
            value = (value as u128 * value as u128 % n as u128) as u64;
            if value == n - 1 {
                passed = true;
                break;
            }
        }
        if !passed {
            return false;
        }
    }
    true
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn half(value: &[u64]) -> Vec<u64> {
    let mut result = value.to_vec();
    BigUint(result.as_mut_slice()).right_shift_assign(1);
    result
}

fn cmp_words(a: &[u64], b: &[u64]) -> Ordering {
    for index in (0..a.len().max(b.len())).rev() {
        match a
            .get(index)
            .copied()
            .unwrap_or(0)
            .cmp(&b.get(index).copied().unwrap_or(0))
        {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

fn mul_scalar_to(input: &[u64], scalar: u64, output: &mut [u64]) {
    debug_assert!(output.len() > input.len());
    output.fill(0);
    let mut carry = 0;
    for (&value, destination) in input.iter().zip(output.iter_mut()) {
        let product = value as u128 * scalar as u128 + carry as u128;
        *destination = product as u64;
        carry = (product >> 64) as u64;
    }
    output[input.len()] = carry;
}

fn add_words_assign(acc: &mut [u64], value: &[u64]) {
    let mut carry = false;
    for (index, destination) in acc.iter_mut().enumerate() {
        let (sum, c0) = destination.overflowing_add(value.get(index).copied().unwrap_or(0));
        let (sum, c1) = sum.overflowing_add(u64::from(carry));
        *destination = sum;
        carry = c0 || c1;
    }
    debug_assert!(!carry);
}

fn sub_words_assign(acc: &mut [u64], value: &[u64]) {
    let mut borrow = false;
    for (index, destination) in acc.iter_mut().enumerate() {
        let (difference, b0) = destination.overflowing_sub(value.get(index).copied().unwrap_or(0));
        let (difference, b1) = difference.overflowing_sub(u64::from(borrow));
        *destination = difference;
        borrow = b0 || b1;
    }
    debug_assert!(!borrow);
}

fn shift_left(value: &mut [u64], shift: u32) -> u64 {
    if shift == 0 {
        return 0;
    }
    let mut carry = 0;
    for word in value {
        let next = *word >> (64 - shift);
        *word = (*word << shift) | carry;
        carry = next;
    }
    carry
}

#[cfg(test)]
mod tests {
    use dashu_int::IBig;

    use super::{ScalarQuotient, half};

    fn words(value: &IBig, length: usize) -> Vec<u64> {
        let radix = IBig::ONE << 64;
        let mut value = value.clone();
        (0..length)
            .map(|_| {
                let word = u64::try_from(&value % &radix).unwrap();
                value >>= 64;
                word
            })
            .collect()
    }

    #[test]
    fn one_word_quotient_normalization_and_half_neighbors_match_integer_division() {
        let mut overestimates = 0;
        for bits in [61usize, 64, 65, 100, 127, 128, 129, 150, 190, 191] {
            let q = (IBig::ONE << bits) - 13u64;
            let q_words = words(&q, bits.div_ceil(64));
            let half_q = half(&q_words);
            let mut rounder = ScalarQuotient::new(&q_words);
            for t in [2u64, 193, (1 << 30) + 3, (1 << 62) - 57] {
                let mut inputs = vec![IBig::ZERO, IBig::ONE, &q / 2u64, &q - 2u64, &q - 1u64];
                for k in [0, 1, t / 3, t / 2, t - 1] {
                    let boundary = (&q * (2 * k + 1)) / IBig::from(2 * t);
                    for adjustment in [-1, 0, 1] {
                        let value = &boundary + adjustment;
                        if value >= IBig::ZERO && value < q {
                            inputs.push(value);
                        }
                    }
                }
                for r in inputs {
                    let expected = u64::try_from((&r * t + &q / 2u64) / &q).unwrap();
                    let actual = rounder.round(&words(&r, q_words.len()), t, &half_q);
                    assert_eq!(actual, expected, "Q bits={bits}, t={t}, r={r}");
                    let length = rounder.normalized_q.len();
                    let leading = ((rounder.numerator[length] as u128) << 64)
                        | rounder.numerator[length - 1] as u128;
                    let estimate = leading / rounder.normalized_q[length - 1] as u128;
                    assert!(estimate >= u128::from(expected));
                    assert!(estimate - u128::from(expected) <= 2);
                    overestimates += usize::from(estimate > u128::from(expected));
                }
            }
        }
        assert!(
            overestimates > 0,
            "fixtures must exercise full-word correction"
        );
    }
}

#[cfg(test)]
mod tests_tensor;
