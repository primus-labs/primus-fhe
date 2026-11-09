//! Native rank-one Hybrid RNS gadget products in `[c0,c1]` plus-phase order.
//!
//! Scheme owners generate role-specific QP columns. This module owns numerical
//! precomputation and allocation-free evaluation; it does not encrypt keys,
//! authenticate secrets or establish circuit noise/security bounds.

use primus_integer::BigUint;
use std::sync::Arc;
use zeroize::Zeroizing;

use primus_decompose::DecompositionConfig;
use primus_factor::{FactorMul, FactorSliceOps, ShoupFactor};
use primus_modulus::BarrettModulus;
use primus_ntt::{
    NttError, NttTable, U64DcrtTable, U64NttPrimeBasisError, validate_u64_ntt_primes,
};
use primus_reduce::{Reduce, ReduceInv, ReduceMulAddSlice, ReduceNeg};
use primus_rns::{
    CenteredBaseConverter, CenteredConversionWorkspace, HybridRNS, HybridRNSPartitioning, RNSBase,
    Residues, RnsError,
};
use primus_shape::PolyLength;

type Base = RNSBase<u64, BarrettModulus<u64>>;

/// Selected evaluation-key representation; prepared handles share numerical resources.
#[derive(Clone)]
pub enum EvaluationKeyConfig {
    /// Signed radix columns in the ciphertext modulus.
    Radix(DecompositionConfig),
    /// Signed radix columns with shared complete numerical preparation.
    PreparedRadix(Arc<crate::radix::NativeRadixParameters>),
    /// Partitioned QP columns with one shared immutable numerical owner.
    Hybrid(Arc<NativeHybridParameters>),
}
impl From<DecompositionConfig> for EvaluationKeyConfig {
    fn from(value: DecompositionConfig) -> Self {
        Self::Radix(value)
    }
}
impl From<Arc<crate::radix::NativeRadixParameters>> for EvaluationKeyConfig {
    fn from(value: Arc<crate::radix::NativeRadixParameters>) -> Self {
        Self::PreparedRadix(value)
    }
}

impl From<Arc<NativeHybridParameters>> for EvaluationKeyConfig {
    fn from(value: Arc<NativeHybridParameters>) -> Self {
        Self::Hybrid(value)
    }
}

/// Componentwise reduction rule used after native QP accumulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HybridModDown {
    /// Exact nearest division by P, as used by ordinary BFV.
    Centered,
    /// Subtract t times the centered lift of t^-1*x_P before division by P.
    PlaintextPreserving(u64),
}

/// Invalid native Hybrid geometry, modulus or ordered-table binding.
#[derive(Debug, thiserror::Error)]
pub enum NativeHybridError {
    /// A complete array length cannot be represented.
    #[error("native Hybrid storage length overflow")]
    LengthOverflow,
    /// Q or P fails native NTT prime validation.
    #[error(transparent)]
    PrimeBasis(#[from] U64NttPrimeBasisError),
    /// Actual Q NTT tables do not match the prepared ring and ordered prefix.
    #[error("native Hybrid Q NTT table mismatch")]
    TableMismatch,
    /// A plaintext-preserving correction needs positive t coprime to every P.
    #[error("native Hybrid plaintext modulus must be positive and coprime to P")]
    PlaintextModulus,
    /// The stored highest-level secret has incompatible shape or residues.
    #[error("native Hybrid secret representation is incompatible with its actual Q tables")]
    SecretRepresentation,
    /// No integer within the declared support represents a stored coefficient.
    #[error("native Hybrid secret coefficient exceeds magnitude support {bound}")]
    SecretSupport {
        /// Declared public magnitude bound.
        bound: u64,
    },
    /// More than one bounded integer represents a stored coefficient.
    #[error(
        "native Hybrid stored Q does not uniquely identify a coefficient within support {bound}"
    )]
    AmbiguousSecret {
        /// Declared public magnitude bound.
        bound: u64,
    },
    /// Invalid RNS bases or partitions.
    #[error(transparent)]
    Rns(#[from] RnsError),
    /// Invalid auxiliary NTT table.
    #[error(transparent)]
    Transform(#[from] NttError<u64>),
}

/// Immutable auxiliary P basis and transforms shared by active Q levels.
pub struct NativeHybridAuxiliary {
    base: Base,
    table: U64DcrtTable,
}

impl NativeHybridAuxiliary {
    /// Prepares P once for several active Q levels in the same ring.
    ///
    /// # Errors
    /// Rejects invalid NTT prime bases or unsupported transforms.
    pub fn try_new(
        poly_length: PolyLength,
        auxiliary_moduli: &[u64],
    ) -> Result<Self, NativeHybridError> {
        validate_u64_ntt_primes(poly_length, auxiliary_moduli)?;
        Self::from_base(poly_length, auxiliary_base(auxiliary_moduli)?)
    }

    fn from_base(poly_length: PolyLength, base: Base) -> Result<Self, NativeHybridError> {
        let table = U64DcrtTable::new(poly_length, base.moduli())?;
        Ok(Self { base, table })
    }
}

/// Immutable QP basis and arithmetic for one actual active Q level.
///
/// The Q base shares its existing CRT allocation; Q NTT tables stay with the
/// scheme context and are borrowed by operations. Different levels can share
/// their P basis and tables, and role keys can share this owner through [`Arc`].
/// No size relation P>Q or P>partition-product is imposed: callers budget the
/// true digit and key errors for their selected P.
pub struct NativeHybridParameters {
    hybrid: HybridRNS<u64, BarrettModulus<u64>>,
    auxiliary: Arc<NativeHybridAuxiliary>,
    p_to_q: CenteredBaseConverter,
    weights: Vec<u64>,
    q_len: usize,
    qp_len: usize,
    key_len: usize,
}

impl NativeHybridParameters {
    /// Prepares one active prefix using fixed full-chain partition geometry.
    ///
    /// Explicit auxiliary primes are computation/key moduli, distinct from
    /// multiplication-only auxiliary bases. Both bases must contain actual NTT
    /// primes. Successful construction establishes numerical compatibility.
    ///
    /// # Errors
    /// Rejects invalid moduli/partitions, noncoprime bases, unsupported transforms
    /// or overflowing complete storage geometry.
    pub fn try_new(
        poly_length: PolyLength,
        base_q: &Base,
        full_q_moduli_count: usize,
        auxiliary_moduli: &[u64],
        decomposition_count: usize,
    ) -> Result<Self, NativeHybridError> {
        validate_u64_ntt_primes(poly_length, base_q.moduli_values())?;
        validate_u64_ntt_primes(poly_length, auxiliary_moduli)?;
        let partitioning = HybridRNSPartitioning::new(full_q_moduli_count, decomposition_count)?;
        let base_p = auxiliary_base(auxiliary_moduli)?;
        let hybrid = HybridRNS::from_bases(base_q, &base_p, partitioning)?;
        let auxiliary = Arc::new(NativeHybridAuxiliary::from_base(poly_length, base_p)?);
        Self::from_hybrid(hybrid, auxiliary)
    }

    /// Prepares an active Q prefix using an existing P basis and transforms.
    ///
    /// The ring length comes from the prepared auxiliary resources. The active
    /// Q basis must be the actual ordered prefix of the full chain.
    ///
    /// # Errors
    /// Rejects invalid Q moduli, incompatible Q/P bases or partitions, and
    /// overflowing complete storage geometry.
    pub fn try_with_auxiliary(
        base_q: &Base,
        full_q_moduli_count: usize,
        auxiliary: Arc<NativeHybridAuxiliary>,
        decomposition_count: usize,
    ) -> Result<Self, NativeHybridError> {
        validate_u64_ntt_primes(auxiliary.table.poly_length(), base_q.moduli_values())?;
        let partitioning = HybridRNSPartitioning::new(full_q_moduli_count, decomposition_count)?;
        let hybrid = HybridRNS::from_bases(base_q, &auxiliary.base, partitioning)?;
        Self::from_hybrid(hybrid, auxiliary)
    }

    fn from_hybrid(
        hybrid: HybridRNS<u64, BarrettModulus<u64>>,
        auxiliary: Arc<NativeHybridAuxiliary>,
    ) -> Result<Self, NativeHybridError> {
        let n = auxiliary.table.poly_length().get();
        let q_len = n
            .checked_mul(hybrid.q_moduli_count())
            .ok_or(NativeHybridError::LengthOverflow)?;
        let qp_len = n
            .checked_mul(hybrid.qp_moduli_count())
            .ok_or(NativeHybridError::LengthOverflow)?;
        let key_len = qp_len
            .checked_mul(2)
            .and_then(|x| x.checked_mul(hybrid.partition_count()))
            .ok_or(NativeHybridError::LengthOverflow)?;
        let weight_len = hybrid
            .qp_moduli_count()
            .checked_mul(hybrid.partition_count())
            .ok_or(NativeHybridError::LengthOverflow)?;
        let mut weights = vec![0; weight_len];
        for (partition, row) in hybrid
            .partitions()
            .zip(weights.chunks_exact_mut(hybrid.qp_moduli_count()))
        {
            for i in partition.q_range() {
                row[i] = hybrid.p_mod_q()[i];
            }
        }
        Ok(Self {
            auxiliary,
            p_to_q: CenteredBaseConverter::try_from_converter(hybrid.mod_down_converter().clone())?,
            hybrid,
            weights,
            q_len,
            qp_len,
            key_len,
        })
    }
    /// Returns this full ciphertext ring length.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.auxiliary.table.poly_length()
    }
    /// Borrows the actual Q/P bases and fixed partition geometry.
    #[must_use]
    pub fn hybrid_rns(&self) -> &HybridRNS<u64, BarrettModulus<u64>> {
        &self.hybrid
    }
    /// Borrows the shared auxiliary P basis and transforms.
    #[must_use]
    pub fn auxiliary(&self) -> &Arc<NativeHybridAuxiliary> {
        &self.auxiliary
    }
    /// Borrows the auxiliary P NTT tables.
    #[must_use]
    pub fn table_p(&self) -> &U64DcrtTable {
        &self.auxiliary.table
    }
    /// Returns one Q polynomial's complete length.
    #[must_use]
    pub fn q_poly_len(&self) -> usize {
        self.q_len
    }
    /// Returns one QP polynomial's complete length.
    #[must_use]
    pub fn qp_poly_len(&self) -> usize {
        self.qp_len
    }
    /// Returns the number of active Hybrid columns.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.hybrid.partition_count()
    }
    /// Returns one native two-component QP column's complete length.
    #[must_use]
    pub fn column_len(&self) -> usize {
        2 * self.qp_len
    }
    /// Returns the full native column matrix length.
    #[must_use]
    pub fn key_len(&self) -> usize {
        self.key_len
    }
    /// Borrows the QP scalar weights for one partition: P in its Q limbs, zero elsewhere.
    ///
    /// # Panics
    /// Panics when the column index is out of range.
    #[must_use]
    pub fn key_weights(&self, index: usize) -> &[u64] {
        assert!(
            index < self.partition_count(),
            "native Hybrid column index out of range"
        );
        &self.weights
            [index * self.hybrid.qp_moduli_count()..(index + 1) * self.hybrid.qp_moduli_count()]
    }
    /// Checks the actual ordered Q prefix and NTT ring before setup/evaluation.
    ///
    /// # Errors
    /// Returns an error for a different ring, too few tables or a modulus mismatch.
    pub fn validate_table(&self, table_q: &U64DcrtTable) -> Result<(), NativeHybridError> {
        if table_q.poly_length() != self.poly_length()
            || table_q.moduli_count() < self.hybrid.q_moduli_count()
        {
            return Err(NativeHybridError::TableMismatch);
        }
        if table_q
            .iter()
            .zip(self.hybrid.q_base().moduli_values())
            .any(|(table, &q)| table.modulus() != q)
        {
            return Err(NativeHybridError::TableMismatch);
        }
        Ok(())
    }
    /// Validates a scheme's ModDown scalar without allocating scratch.
    ///
    /// # Errors
    /// Rejects a nonpositive plaintext scalar or a scalar not coprime to P.
    pub fn validate_mod_down(&self, mode: HybridModDown) -> Result<(), NativeHybridError> {
        let t = match mode {
            HybridModDown::Centered => 1,
            HybridModDown::PlaintextPreserving(t) => t,
        };
        if t == 0
            || self
                .hybrid
                .p_base()
                .moduli_values()
                .iter()
                .any(|&p| gcd(t, p) != 1)
        {
            return Err(NativeHybridError::PlaintextModulus);
        }
        Ok(())
    }
    /// Transforms one complete QP polynomial with the actual context Q tables.
    ///
    /// # Panics
    /// Rejects incompatible tables or an incorrect complete length before writes.
    pub fn transform_qp_assign(&self, table_q: &U64DcrtTable, polynomial: &mut [u64]) {
        self.validate_table(table_q)
            .expect("native Hybrid Q table mismatch");
        assert_eq!(polynomial.len(), self.qp_len);
        self.transform_qp_kernel(table_q, polynomial, false);
    }
    /// Inversely transforms one complete QP polynomial.
    ///
    /// # Panics
    /// Inherits [`Self::transform_qp_assign`]'s checks.
    pub fn inverse_transform_qp_assign(&self, table_q: &U64DcrtTable, polynomial: &mut [u64]) {
        self.validate_table(table_q)
            .expect("native Hybrid Q table mismatch");
        assert_eq!(polynomial.len(), self.qp_len);
        self.transform_qp_kernel(table_q, polynomial, true);
    }
    /// Extends the actual highest-Q bounded secret to this active QP NTT basis.
    ///
    /// This setup-only operation accepts exactly one complete source secret
    /// polynomial, using the supplied source base's actual NTT tables. The
    /// active Q must match its ordered prefix. It preserves those Q NTT limbs
    /// and constructs only P limbs; no Q tables or bases are rebuilt.
    ///
    /// Each coefficient must have one unique integer representative in
    /// `[-bound,bound]`. A small-support fast path decodes the first Q limb and
    /// verifies every other source limb. The general path reconstructs in the
    /// full stored Q and checks both positive and negative bounded candidates,
    /// rejecting ambiguity even when distribution metadata appears compatible.
    /// The returned secret and every temporary coefficient/CRT buffer erase on
    /// drop, including errors and unwind. No complete secret is exposed through
    /// a diagnostic accessor; this is the real QP key-generation input.
    ///
    /// # Errors
    /// Rejects incompatible source geometry/table/active prefix, noncanonical
    /// residues, inconsistent small lifts, out-of-support or ambiguous integers.
    pub fn extend_bounded_secret_to_qp(
        &self,
        source_ntt: &[u64],
        source_base: &Base,
        source_table: &U64DcrtTable,
        bound: u64,
    ) -> Result<Zeroizing<Vec<u64>>, NativeHybridError> {
        let n = self.poly_length().get();
        self.validate_table(source_table)?;
        let count = source_base.moduli_count();
        if count != source_table.moduli_count()
            || source_ntt.len()
                != source_base
                    .moduli_count()
                    .checked_mul(n)
                    .ok_or(NativeHybridError::LengthOverflow)?
            || source_table
                .iter()
                .zip(source_base.moduli_values())
                .any(|(table, &q)| table.modulus() != q)
        {
            return Err(NativeHybridError::SecretRepresentation);
        }
        if source_ntt
            .chunks_exact(n)
            .zip(source_base.moduli_values())
            .any(|(limb, &q)| limb.iter().any(|&x| x >= q))
        {
            return Err(NativeHybridError::SecretRepresentation);
        }
        let mut magnitude = Zeroizing::new(vec![0u64; n]);
        let mut negative = Zeroizing::new(vec![0u8; n]);
        let first_q = source_base.moduli_values()[0];
        if bound < first_q / 2 {
            let mut coefficient = Zeroizing::new(source_ntt[..n].to_vec());
            source_table.ntt_tables()[0].inverse_transform_slice(&mut coefficient);
            for ((&value, magnitude), negative) in coefficient
                .iter()
                .zip(magnitude.iter_mut())
                .zip(negative.iter_mut())
            {
                let is_negative = value > first_q / 2;
                *magnitude = if is_negative { first_q - value } else { value };
                *negative = u8::from(is_negative);
                if *magnitude > bound {
                    return Err(NativeHybridError::SecretSupport { bound });
                }
            }
            // A bounded first-limb lift is not evidence of CRT coherence.
            // Re-encode it in each remaining actual source Q table once.
            for ((table, q), input) in source_table
                .iter()
                .zip(source_base.moduli())
                .zip(source_ntt.chunks_exact(n))
                .skip(1)
            {
                encode_secret(&magnitude, &negative, q, &mut coefficient);
                table.transform_slice(&mut coefficient);
                if coefficient.as_slice() != input {
                    return Err(NativeHybridError::SecretRepresentation);
                }
            }
        } else {
            let mut coefficients = Zeroizing::new(source_ntt.to_vec());
            for (table, limb) in source_table.iter().zip(coefficients.chunks_exact_mut(n)) {
                table.inverse_transform_slice(limb);
            }
            let width = source_base.big_uint_value_len();
            let mut residues = Zeroizing::new(vec![0u64; count]);
            let mut value = Zeroizing::new(vec![0u64; width]);
            let mut opposite = Zeroizing::new(vec![0u64; width]);
            let modulus = source_base.moduli_product();
            for index in 0..n {
                for (residue, limb) in residues.iter_mut().zip(coefficients.chunks_exact(n)) {
                    *residue = limb[index];
                }
                source_base.compose_to(Residues(&residues), BigUint(&mut value));
                let mut borrow = false;
                for ((out, &q), &x) in opposite.iter_mut().zip(modulus.digits()).zip(value.iter()) {
                    let (difference, b1) = q.overflowing_sub(x);
                    let (difference, b2) = difference.overflowing_sub(u64::from(borrow));
                    *out = difference;
                    borrow = b1 || b2;
                }
                debug_assert!(!borrow);
                let positive_fits = within_u64_support(&value, bound);
                let negative_fits = within_u64_support(&opposite, bound);
                match (positive_fits, negative_fits) {
                    (true, false) => {
                        magnitude[index] = value[0];
                    }
                    (false, true) => {
                        magnitude[index] = opposite[0];
                        negative[index] = 1;
                    }
                    (true, true) => return Err(NativeHybridError::AmbiguousSecret { bound }),
                    (false, false) => return Err(NativeHybridError::SecretSupport { bound }),
                }
            }
        }
        let mut output = Zeroizing::new(vec![0u64; self.qp_len]);
        output[..self.q_len].copy_from_slice(&source_ntt[..self.q_len]);
        for ((table, q), limb) in self
            .table_p()
            .iter()
            .zip(self.hybrid.p_base().moduli())
            .zip(output[self.q_len..].chunks_exact_mut(n))
        {
            encode_secret(&magnitude, &negative, q, limb);
            table.transform_slice(limb);
        }
        Ok(output)
    }
    fn transform_qp_kernel(&self, table_q: &U64DcrtTable, polynomial: &mut [u64], inverse: bool) {
        let (q, p) = polynomial.split_at_mut(self.q_len);
        if inverse {
            table_q.inverse_transform_prefix_slice(q);
            self.table_p().inverse_transform_prefix_slice(p);
        } else {
            table_q.transform_prefix_slice(q);
            self.table_p().transform_prefix_slice(p);
        }
    }
}

fn auxiliary_base(moduli: &[u64]) -> Result<Base, RnsError> {
    Base::from_owned_moduli(moduli.iter().copied().map(BarrettModulus::new).collect())
}

/// One native two-component Hybrid gadget-product request and its scratch.
///
/// The immutable parameter owner is shared; only the context's Q NTT table is
/// borrowed. Columns remain with their scheme key. The result has phase
/// approximately input*h under the destination secret when column phases are
/// w_j*h+noise, with w_j given by key_weights; complete error and key identity belong to callers.
pub struct NativeHybridProduct<'a> {
    parameters: Arc<NativeHybridParameters>,
    table_q: &'a U64DcrtTable,
    mode: HybridModDown,
    t_inv_p: Vec<ShoupFactor<u64>>,
    q_factors: Vec<(ShoupFactor<u64>, ShoupFactor<u64>)>,
    // Partition ModUp reads Q coefficients before ModDown overwrites this
    // complete buffer with each component's P-to-Q correction.
    q_scratch: Vec<u64>,
    accumulator: Vec<u64>,
    mod_up_limb: Vec<u64>,
    mod_up_scratch: Vec<u64>,
    conversion: CenteredConversionWorkspace,
}
impl<'a> NativeHybridProduct<'a> {
    /// Binds actual Q tables, shares the parameter owner and prepares all scratch.
    ///
    /// # Errors
    /// Rejects incompatible tables or nonpositive/noninvertible plaintext scale.
    pub fn try_new(
        parameters: &Arc<NativeHybridParameters>,
        table_q: &'a U64DcrtTable,
        mode: HybridModDown,
    ) -> Result<Self, NativeHybridError> {
        parameters.validate_table(table_q)?;
        let t = match mode {
            HybridModDown::Centered => 1,
            HybridModDown::PlaintextPreserving(t) => t,
        };
        parameters.validate_mod_down(mode)?;
        let t_inv_p = parameters
            .hybrid
            .p_base()
            .moduli()
            .iter()
            .map(|p| ShoupFactor::new(p.reduce_inv(p.reduce(t)), p.value()))
            .collect();
        let q_factors = parameters
            .hybrid
            .q_base()
            .moduli()
            .iter()
            .zip(parameters.hybrid.inv_p_mod_q())
            .map(|(q, &p_inv)| {
                let inverse = ShoupFactor::new(p_inv, q.value());
                let correction = q.reduce_neg(inverse.factor_mul_modulo(q.reduce(t), q.value()));
                (inverse, ShoupFactor::new(correction, q.value()))
            })
            .collect();
        Ok(Self {
            parameters: Arc::clone(parameters),
            table_q,
            mode,
            t_inv_p,
            q_factors,
            q_scratch: vec![0; parameters.q_len],
            accumulator: vec![0; 2 * parameters.qp_len],
            mod_up_limb: vec![0; parameters.poly_length().get()],
            mod_up_scratch: vec![
                0;
                parameters
                    .hybrid
                    .max_mod_up_scratch_len(parameters.poly_length().get())
            ],
            conversion: parameters.p_to_q.workspace(parameters.poly_length().get()),
        })
    }
    /// Writes a complete native `[c0,c1]` gadget product in Q NTT representation.
    ///
    /// `input` contains one Q NTT polynomial and `columns` contains exactly
    /// partition_count native QP ciphertexts, in partition/c0/c1/modulus order.
    /// Canonical residues, the actual source/target secrets and Q/P NTT
    /// convention are caller contracts. No allocation occurs online.
    ///
    /// # Panics
    /// All complete input/key/output lengths are checked before any writes.
    pub fn product_to(&mut self, input: &[u64], columns: &[u64], output: &mut [u64]) {
        let p = &self.parameters;
        assert_eq!(input.len(), p.q_len);
        assert_eq!(columns.len(), p.key_len);
        assert_eq!(output.len(), 2 * p.q_len);
        let n = p.poly_length().get();
        let table_p = p.table_p();
        self.q_scratch.copy_from_slice(input);
        self.accumulator.fill(0);
        for (table, values) in self.table_q.iter().zip(self.q_scratch.chunks_exact_mut(n)) {
            table.inverse_transform_slice(values)
        }
        for (partition, column) in p
            .hybrid
            .partitions()
            .zip(columns.chunks_exact(p.column_len()))
        {
            for index in partition.q_range() {
                add_limb(
                    &mut self.accumulator,
                    column,
                    &input[index * n..(index + 1) * n],
                    p.qp_len,
                    index,
                    &p.hybrid.qp_base().moduli()[index],
                );
            }
            let scratch_len = partition.mod_up_scratch_len(n);
            partition.for_each_approx_mod_up_complement_limb(
                &self.q_scratch,
                &mut self.mod_up_limb,
                n,
                &mut self.mod_up_scratch[..scratch_len],
                |index, limb| {
                    let table = if index < p.hybrid.q_moduli_count() {
                        &self.table_q.ntt_tables()[index]
                    } else {
                        &table_p.ntt_tables()[index - p.hybrid.q_moduli_count()]
                    };
                    table.transform_slice(limb);
                    add_limb(
                        &mut self.accumulator,
                        column,
                        limb,
                        p.qp_len,
                        index,
                        &p.hybrid.qp_base().moduli()[index],
                    );
                },
            );
        }
        for (accumulator, output) in self
            .accumulator
            .chunks_exact_mut(p.qp_len)
            .zip(output.chunks_exact_mut(p.q_len))
        {
            let (acc_q, acc_p) = accumulator.split_at_mut(p.q_len);
            for ((table, limb), factor) in table_p
                .iter()
                .zip(acc_p.chunks_exact_mut(n))
                .zip(&self.t_inv_p)
            {
                table.inverse_transform_slice(limb);
                if self.mode != HybridModDown::Centered {
                    for value in limb {
                        *value = factor.factor_mul_modulo(*value, table.modulus())
                    }
                }
            }
            p.p_to_q
                .convert_to(acc_p, &mut self.q_scratch, n, &mut self.conversion);
            for ((((table, correction), acc), out), (inverse, minus_scaled_inverse)) in self
                .table_q
                .iter()
                .zip(self.q_scratch.chunks_exact_mut(n))
                .zip(acc_q.chunks_exact(n))
                .zip(output.chunks_exact_mut(n))
                .zip(&self.q_factors)
            {
                table.transform_slice(correction);
                // Compute P^-1 * (acc - t * correction) with two Shoup passes.
                let q = table.modulus();
                inverse.factor_mul_slice_to(acc, out, q);
                minus_scaled_inverse.add_factor_mul_slice_assign(out, correction, q);
            }
        }
    }
}
fn add_limb(
    accumulator: &mut [u64],
    column: &[u64],
    digit: &[u64],
    qp_len: usize,
    index: usize,
    modulus: &BarrettModulus<u64>,
) {
    let start = index * digit.len();
    for component in 0..2 {
        let offset = component * qp_len + start;
        let range = offset..offset + digit.len();
        modulus.reduce_add_mul_slice_assign(&mut accumulator[range.clone()], &column[range], digit);
    }
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b)
    }
    a
}

fn within_u64_support(words: &[u64], bound: u64) -> bool {
    words[0] <= bound && words[1..].iter().all(|&word| word == 0)
}
fn encode_secret(
    magnitudes: &[u64],
    negative: &[u8],
    modulus: &BarrettModulus<u64>,
    output: &mut [u64],
) {
    for ((out, &magnitude), &negative) in output.iter_mut().zip(magnitudes).zip(negative) {
        let reduced = modulus.reduce(magnitude);
        *out = if negative != 0 && reduced != 0 {
            modulus.value() - reduced
        } else {
            reduced
        };
    }
}
