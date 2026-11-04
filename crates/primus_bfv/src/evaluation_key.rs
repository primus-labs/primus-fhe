//! Scheme-owned evaluation keys in native `[c0,c1]` plus-phase order.
//! Radix keys live in Q; Hybrid keys live in QP and divide by P only inside
//! their native key product. No ordinary operation crosses a raw GLWE bridge.

use crate::{BfvCiphertext, BfvClient, BfvContext, BfvQuadraticCiphertext};
use primus_data::{Data, DataMut};
use primus_decompose::{ApproxSignedBasisError, big_integer::BigUintApproxSignedBasis};
pub use primus_lattice::hybrid::EvaluationKeyConfig as BfvEvaluationKeyConfig;
use primus_lattice::hybrid::{
    EvaluationKeyConfig, HybridModDown, NativeHybridError, NativeHybridParameters,
    NativeHybridProduct,
};
use primus_lattice::{
    GlweSizeError, RnsGadgetSize, RnsGlweSize, glev::DcrtGlev, glwe::DcrtGlwe,
    workspace::DcrtGlevMulWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::{ReduceAdd, ReduceMul, ReduceSub};
use primus_rns::Residues;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Invalid BFV evaluation-key parameters or numerical binding.
#[derive(Debug, thiserror::Error)]
pub enum BfvEvaluationKeyError {
    /// A requested context level was not prepared.
    #[error("BFV key level {requested} is outside the {available} prepared levels")]
    Level {
        /// Requested level.
        requested: usize,
        /// Number of prepared levels.
        available: usize,
    },
    /// The full ciphertext polynomial length differs.
    #[error("BFV polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLength {
        /// Expected polynomial length.
        expected: usize,
        /// Supplied polynomial length.
        actual: usize,
    },
    /// The plaintext modulus differs.
    #[error("BFV plaintext modulus mismatch: expected {expected}, got {actual}")]
    PlainModulus {
        /// Expected t.
        expected: u64,
        /// Supplied t.
        actual: u64,
    },
    /// A batching encoder's plaintext capacity exceeds the ciphertext ring.
    #[cfg(feature = "batching")]
    #[error("BFV slot capacity {actual} exceeds full polynomial length {maximum}")]
    SlotCapacity {
        /// Largest supported plaintext capacity.
        maximum: usize,
        /// Supplied plaintext capacity.
        actual: usize,
    },
    /// Ordered Q bases have different lengths.
    #[error("BFV modulus count mismatch: expected {expected}, got {actual}")]
    ModuliCount {
        /// Expected retained modulus count.
        expected: usize,
        /// Supplied retained modulus count.
        actual: usize,
    },
    /// An ordered ciphertext modulus differs.
    #[error("BFV modulus mismatch at {index}: expected {expected}, got {actual}")]
    Modulus {
        /// Ordered modulus index.
        index: usize,
        /// Expected modulus.
        expected: u64,
        /// Supplied modulus.
        actual: u64,
    },
    /// Signed digit lifting needs B strictly below every retained prime.
    #[error("BFV gadget radix {radix} is not below ciphertext modulus {modulus}")]
    Radix {
        /// Gadget radix.
        radix: u64,
        /// Rejected retained modulus.
        modulus: u64,
    },
    /// An automorphism exponent must be odd and below 2N.
    #[error("BFV automorphism exponent {exponent} must be odd and below {twice_n}")]
    Exponent {
        /// Supplied exponent.
        exponent: usize,
        /// Exclusive upper bound.
        twice_n: usize,
    },
    /// The radix or retained digit count is incompatible with Q.
    #[error(transparent)]
    Decomposition(#[from] ApproxSignedBasisError),
    /// Invalid native Hybrid numerical parameters.
    #[error(transparent)]
    Hybrid(#[from] NativeHybridError),
    /// Key noise cannot be represented in one auxiliary modulus.
    #[error("BFV Hybrid noise support {bound} must be below key modulus {modulus}")]
    NoiseSupport {
        /// Maximum noise magnitude.
        bound: u64,
        /// Rejected key modulus.
        modulus: u64,
    },
    /// Complete evaluation-key storage would overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
}

/// One native BFV key's actual Q level, decomposition and public columns.
/// Radix metadata and Hybrid P tables are shared immutable owners; the actual
/// Q NTT tables remain borrowed from the context.
struct NativeEvaluationKey {
    level: usize,
    t: u64,
    moduli: Vec<u64>,
    n: usize,
    basis: NativeEvaluationBasis,
    columns: Vec<u64>,
}

#[derive(Clone)]
enum NativeEvaluationBasis {
    Radix(Arc<RadixMetadata>),
    Hybrid(Arc<NativeHybridParameters>),
}

struct RadixMetadata {
    size: RnsGadgetSize,
    basis: BigUintApproxSignedBasis<u64>,
    weights: Vec<u64>,
}

impl NativeEvaluationKey {
    fn prepare(
        context: &BfvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
    ) -> Result<Self, BfvEvaluationKeyError> {
        let mut key = Self::prepare_metadata(context, level, config)?;
        key.columns.resize(key.key_len(), 0);
        Ok(key)
    }

    fn prepare_metadata(
        context: &BfvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
    ) -> Result<Self, BfvEvaluationKeyError> {
        validate_level(context, level)?;
        let base = context.codec(level).base_q();
        let n = context.parameters().poly_length().get();
        let basis = match config.into() {
            EvaluationKeyConfig::Radix(config) => {
                let basis = BigUintApproxSignedBasis::try_new(
                    base.moduli_product(),
                    config.log_basis,
                    config.level_count,
                )?;
                for q in base.moduli() {
                    if basis.basis_value() >= q.value() {
                        return Err(BfvEvaluationKeyError::Radix {
                            radix: basis.basis_value(),
                            modulus: q.value(),
                        });
                    }
                }
                let size = RnsGadgetSize::try_new(
                    RnsGlweSize::try_new(
                        context.parameters().size().glwe_size(),
                        base.moduli_count(),
                    )?,
                    basis.level_count(),
                )?;
                let mut weights = vec![0; basis.level_count().get() * base.moduli_count()];
                for (scalar, out) in basis
                    .scalar_iter()
                    .zip(weights.chunks_exact_mut(base.moduli_count()))
                {
                    base.decompose_to(primus_integer::BigUint(scalar), Residues(out));
                }
                NativeEvaluationBasis::Radix(Arc::new(RadixMetadata {
                    size,
                    basis,
                    weights,
                }))
            }
            EvaluationKeyConfig::Hybrid(parameters) => {
                validate_numeric_context(
                    parameters.poly_length().get(),
                    context.codec(level).t(),
                    parameters.hybrid_rns().q_base().moduli_values(),
                    context,
                    level,
                )?;
                let bound = context
                    .parameters()
                    .encryption_parameters()
                    .noise_distribution()
                    .maximum_magnitude();
                for &modulus in parameters.hybrid_rns().qp_base().moduli_values() {
                    if bound >= modulus {
                        return Err(BfvEvaluationKeyError::NoiseSupport { bound, modulus });
                    }
                }
                NativeEvaluationBasis::Hybrid(parameters)
            }
        };
        Ok(Self {
            level,
            t: context.codec(level).t(),
            moduli: base.moduli_values().to_vec(),
            n,
            basis,
            columns: Vec::new(),
        })
    }

    fn key_poly_len(&self) -> usize {
        match &self.basis {
            NativeEvaluationBasis::Radix(_) => self.n * self.moduli.len(),
            NativeEvaluationBasis::Hybrid(p) => p.qp_poly_len(),
        }
    }
    fn column_count(&self) -> usize {
        match &self.basis {
            NativeEvaluationBasis::Radix(p) => p.basis.level_count().get(),
            NativeEvaluationBasis::Hybrid(p) => p.partition_count(),
        }
    }
    fn key_len(&self) -> usize {
        2 * self.key_poly_len() * self.column_count()
    }
    fn key_moduli<'a>(&'a self, context: &'a BfvContext) -> &'a [BarrettModulus<u64>] {
        match &self.basis {
            NativeEvaluationBasis::Radix(_) => context.codec(self.level).base_q().moduli(),
            NativeEvaluationBasis::Hybrid(p) => p.hybrid_rns().qp_base().moduli(),
        }
    }
    fn key_moduli_values<'a>(&'a self, context: &'a BfvContext) -> &'a [u64] {
        match &self.basis {
            NativeEvaluationBasis::Radix(_) => context.codec(self.level).moduli_values(),
            NativeEvaluationBasis::Hybrid(p) => p.hybrid_rns().qp_base().moduli_values(),
        }
    }
    fn weights(&self, index: usize) -> &[u64] {
        match &self.basis {
            NativeEvaluationBasis::Radix(p) => {
                &p.weights[index * self.moduli.len()..(index + 1) * self.moduli.len()]
            }
            NativeEvaluationBasis::Hybrid(p) => p.key_weights(index),
        }
    }
    fn transform(&self, context: &BfvContext, poly: &mut [u64], inverse: bool) {
        match &self.basis {
            NativeEvaluationBasis::Radix(_) => {
                for (table, limb) in context.table().iter().zip(poly.chunks_exact_mut(self.n)) {
                    if inverse {
                        table.inverse_transform_slice(limb);
                    } else {
                        table.transform_slice(limb);
                    }
                }
            }
            NativeEvaluationBasis::Hybrid(p) => {
                if inverse {
                    p.inverse_transform_qp_assign(context.table(), poly);
                } else {
                    p.transform_qp_assign(context.table(), poly);
                }
            }
        }
    }
    fn noise<R: rand::Rng + rand::CryptoRng>(&self, context: &BfvContext, rng: &mut R) -> Vec<u64> {
        let mut out = vec![0; self.key_poly_len()];
        context
            .parameters()
            .encryption_parameters()
            .sample_noise_to(&mut out, self.key_moduli_values(context), rng);
        self.transform(context, &mut out, false);
        out
    }
    fn secret(&self, client: &BfvClient<'_>) -> Result<Zeroizing<Vec<u64>>, BfvEvaluationKeyError> {
        let input = client
            .secret_key()
            .iter_dcrt_poly()
            .next()
            .expect("rank-one secret");
        if matches!(self.basis, NativeEvaluationBasis::Radix(_)) {
            return Ok(Zeroizing::new(
                input.as_ref()[..self.n * self.moduli.len()].to_vec(),
            ));
        }
        let NativeEvaluationBasis::Hybrid(parameters) = &self.basis else {
            unreachable!("established Hybrid branch");
        };
        let bound = client
            .context
            .parameters()
            .encryption_parameters()
            .secret_key_sampler()
            .maximum_magnitude();
        Ok(parameters.extend_bounded_secret_to_qp(
            input.as_ref(),
            client.context.parameters().base_q(),
            client.context.table(),
            bound,
        )?)
    }

    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        mut self,
        client: &BfvClient<'_>,
        source: &[u64],
        rng: &mut R,
    ) -> Result<Self, BfvEvaluationKeyError> {
        let context = client.context;
        if matches!(self.basis, NativeEvaluationBasis::Radix(_)) {
            let len = self.key_poly_len();
            for index in 0..self.column_count() {
                let mut output =
                    BfvCiphertext::new(&mut self.columns[index * 2 * len..(index + 1) * 2 * len]);
                client.encrypt_zeros_at_level_to(&mut output, self.level, rng);
                let weights = match &self.basis {
                    NativeEvaluationBasis::Radix(p) => {
                        &p.weights[index * self.moduli.len()..(index + 1) * self.moduli.len()]
                    }
                    _ => unreachable!(),
                };
                let (mut c0, _) = output.c0_c1_mut(len);
                c0.add_mul_scalar_assign(
                    &DcrtPolynomial(source),
                    weights,
                    self.n,
                    context.codec(self.level).base_q().moduli(),
                );
            }
        } else {
            let target = self.secret(client)?;
            let len = self.key_poly_len();
            let uniforms: Vec<_> = self
                .key_moduli_values(context)
                .iter()
                .map(|&q| rand::distr::Uniform::new(0, q).expect("validated modulus"))
                .collect();
            for index in 0..self.column_count() {
                let mut body = self.noise(context, rng);
                let NativeEvaluationBasis::Hybrid(parameters) = self.basis.clone() else {
                    unreachable!("hybrid branch");
                };
                let weights = parameters.key_weights(index);
                let moduli = parameters.hybrid_rns().qp_base().moduli();
                let column = &mut self.columns[index * 2 * len..(index + 1) * 2 * len];
                let (out0, out1) = column.split_at_mut(len);
                primus_distr::sample_crt_uniform_values_to(out1, self.n, &uniforms, rng);
                for ((((body, mask), secret), source), (&weight, modulus)) in body
                    .chunks_exact_mut(self.n)
                    .zip(out1.chunks_exact(self.n))
                    .zip(target.chunks_exact(self.n))
                    .zip(source.chunks_exact(self.n))
                    .zip(weights.iter().zip(moduli))
                {
                    for (((out, &mask), &secret), &source) in
                        body.iter_mut().zip(mask).zip(secret).zip(source)
                    {
                        *out = modulus.reduce_add(
                            modulus.reduce_sub(*out, modulus.reduce_mul(mask, secret)),
                            modulus.reduce_mul(weight, source),
                        );
                    }
                }
                out0.copy_from_slice(&body);
            }
        }
        Ok(self)
    }
    fn empty(&self) -> Self {
        Self {
            level: self.level,
            t: self.t,
            moduli: self.moduli.clone(),
            n: self.n,
            basis: self.basis.clone(),
            columns: vec![0; self.key_len()],
        }
    }
    fn validate(&self, context: &BfvContext) -> Result<(), BfvEvaluationKeyError> {
        validate_level(context, self.level)?;
        validate_numeric_context(self.n, self.t, &self.moduli, context, self.level)
    }
}

impl BfvContext {
    /// Prepares shared auxiliary key resources at one actual level.
    /// Computation-only BFV multiplication bases are unrelated to this key P.
    ///
    /// # Errors
    /// Rejects unsupported levels, incompatible partitions or invalid auxiliary NTT bases.
    pub fn hybrid_key_parameters(
        &self,
        level: usize,
        decomposition_count: usize,
        auxiliary_moduli: &[u64],
    ) -> Result<Arc<NativeHybridParameters>, BfvEvaluationKeyError> {
        validate_level(self, level)?;
        Ok(Arc::new(NativeHybridParameters::try_new(
            self.parameters().poly_length(),
            self.codec(level).base_q(),
            self.parameters().base_q().moduli_count(),
            auxiliary_moduli,
            decomposition_count,
        )?))
    }
}

/// Public role columns encrypting gadget multiples of s² under s.
///
/// Radix columns are unscaled in Q. Hybrid QP columns include P in their
/// partition weights; native ModDown removes P without a BFV message scale.
/// Construction reveals correlated evaluation keys; their security assumption
/// is additional to the fresh-ciphertext RLWE assumption.
pub struct BfvRelinearizationKey {
    key: NativeEvaluationKey,
}

impl BfvRelinearizationKey {
    /// Returns the level for which these columns were generated.
    #[must_use]
    pub(crate) fn level(&self) -> usize {
        self.key.level
    }
}

/// Public role columns encrypting a source secret under the target secret.
/// Hybrid columns use the separate key modulus QP, as described on
/// [`BfvRelinearizationKey`].
pub struct BfvKeySwitchingKey {
    key: NativeEvaluationKey,
}

impl BfvKeySwitchingKey {
    /// Returns the exact prepared level at which this key is consumed.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }
}

/// Public role columns encrypting σ(s) under s for one odd automorphism.
/// Hybrid columns use the separate key modulus QP.
pub struct BfvAutomorphismKey {
    key: NativeEvaluationKey,
    exponent: usize,
    permutation: NttAutomorphismPermutation,
}

impl BfvAutomorphismKey {
    /// Returns the exact prepared level at which this key is consumed.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Returns the odd substitution exponent in `X -> X^exponent`.
    #[must_use]
    pub fn exponent(&self) -> usize {
        self.exponent
    }
}

impl BfvClient<'_> {
    /// Generates g_j*s²+e_j columns under this client's actual secret.
    ///
    /// Temporary secret-square storage is erased on return or unwind.
    /// # Errors
    /// Rejects unsupported levels, radix/Hybrid geometry, secret support or
    /// unrepresentable key noise before sampling.
    pub fn relinearization_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvRelinearizationKey, BfvEvaluationKeyError> {
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let secret = key.secret(self)?;
        let mut square = Zeroizing::new(secret.to_vec());
        DcrtPolynomial(square.as_mut_slice()).mul_assign(
            &DcrtPolynomial(secret.as_slice()),
            key.n,
            key.key_moduli(self.context),
        );
        Ok(BfvRelinearizationKey {
            key: key.encrypt(self, &square, rng)?,
        })
    }

    /// Generates g_j*σ(s)+e_j columns for X -> X^exponent under s.
    ///
    /// Temporary transformed-secret storage is erased on return or unwind.
    /// # Errors
    /// Rejects invalid exponents, levels or decomposition before sampling.
    pub fn automorphism_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        exponent: usize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvAutomorphismKey, BfvEvaluationKeyError> {
        let n = self.context.parameters().poly_length().get();
        if exponent >= 2 * n || exponent & 1 == 0 {
            return Err(BfvEvaluationKeyError::Exponent {
                exponent,
                twice_n: 2 * n,
            });
        }
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let permutation =
            NttAutomorphismPermutation::new(exponent, self.context.parameters().poly_length());
        let secret = key.secret(self)?;
        let mut transformed = Zeroizing::new(vec![0; key.key_poly_len()]);
        for (input, output) in secret.chunks_exact(n).zip(transformed.chunks_exact_mut(n)) {
            permutation.apply_to(input, output);
        }
        Ok(BfvAutomorphismKey {
            key: key.encrypt(self, &transformed, rng)?,
            exponent,
            permutation,
        })
    }

    /// Generates a key rotating each plaintext row left by signed `steps`.
    ///
    /// Negative steps rotate right; steps wrap modulo half the encoder capacity.
    /// A smaller plaintext subring is supported without resizing the secret or
    /// ciphertext ring. The key retains the selected level and can be bound with
    /// [`BfvAutomorphism::try_new`]. No encoder table or scratch is cloned.
    ///
    /// # Errors
    /// Rejects a different plaintext modulus or capacity above N, then applies
    /// [`Self::automorphism_key`]'s checks. All errors precede random sampling.
    #[cfg(feature = "batching")]
    pub fn row_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        steps: isize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvAutomorphismKey, BfvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.rotation_exponent(steps), config, rng)
    }

    /// Generates a key swapping the encoder's two rows without reversing them.
    /// The geometry, level and pre-sampling error checks are
    /// [`Self::row_rotation_key`]'s; no rotation-step configuration is needed.
    #[cfg(feature = "batching")]
    pub fn row_swap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvAutomorphismKey, BfvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.row_swap_exponent(), config, rng)
    }

    #[cfg(feature = "batching")]
    fn validate_batching_encoder(
        &self,
        encoder: &primus_encoding::BatchingEncoder,
    ) -> Result<(), BfvEvaluationKeyError> {
        let expected = self.context.parameters().codec().t();
        let actual = encoder.plain_modulus();
        if actual != expected {
            return Err(BfvEvaluationKeyError::PlainModulus { expected, actual });
        }
        let maximum = self.context.parameters().poly_length().get();
        let actual = encoder.slot_capacity();
        if actual > maximum {
            return Err(BfvEvaluationKeyError::SlotCapacity { maximum, actual });
        }
        Ok(())
    }

    /// Generates a key switching source ciphertexts to this client's secret.
    ///
    /// # Correctness
    /// The callers maintain the intended source/target secret identities and
    /// matching NTT representation. Numeric equality does not establish identity.
    /// # Errors
    /// Rejects different N, t, ordered level bases or decomposition before sampling.
    pub fn key_switching_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        source: &BfvClient<'_>,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BfvKeySwitchingKey, BfvEvaluationKeyError> {
        validate_level(self.context, level)?;
        validate_level(source.context, level)?;
        validate_numeric_context(
            self.context.parameters().poly_length().get(),
            self.context.parameters().codec().t(),
            self.context.codec(level).base_q().moduli_values(),
            source.context,
            level,
        )?;
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let secret = key.secret(source)?;
        Ok(BfvKeySwitchingKey {
            key: key.encrypt(self, &secret, rng)?,
        })
    }
}

/// Prepared native product. The radix GLev kernel is only a
/// componentwise linear sum: its temporary views do not invoke raw b-a*s phase,
/// mask/body combination, or a ciphertext sign conversion.
struct NativeGadgetProduct<'a> {
    context: &'a BfvContext,
    key: &'a NativeEvaluationKey,
    coefficient: Vec<u64>,
    workspace: NativeProductWorkspace<'a>,
}

enum NativeProductWorkspace<'a> {
    Radix(DcrtGlevMulWorkspace<u64>),
    Hybrid(NativeHybridProduct<'a>),
}
impl<'a> NativeProductWorkspace<'a> {
    fn try_new(
        context: &'a BfvContext,
        key: &NativeEvaluationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(match &key.basis {
            NativeEvaluationBasis::Radix(p) => Self::Radix(DcrtGlevMulWorkspace::new(
                p.size,
                context.codec(key.level).base_q(),
            )),
            NativeEvaluationBasis::Hybrid(p) => Self::Hybrid(NativeHybridProduct::try_new(
                p,
                context.table(),
                HybridModDown::Centered,
            )?),
        })
    }
}

fn native_product_to<B: DataMut<Elem = u64>>(
    context: &BfvContext,
    key: &NativeEvaluationKey,
    coefficient: &mut [u64],
    workspace: &mut NativeProductWorkspace<'_>,
    input: &[u64],
    permutation: Option<&NttAutomorphismPermutation>,
    output: &mut BfvCiphertext<B>,
) {
    let n = key.n;
    if let Some(permutation) = permutation {
        for (input, output) in input.chunks_exact(n).zip(coefficient.chunks_exact_mut(n)) {
            permutation.apply_to(input, output);
        }
    } else {
        coefficient.copy_from_slice(input);
    }
    match (&key.basis, workspace) {
        (NativeEvaluationBasis::Radix(p), NativeProductWorkspace::Radix(workspace)) => {
            for (table, limb) in context.table().iter().zip(coefficient.chunks_exact_mut(n)) {
                table.inverse_transform_slice(limb);
            }
            DcrtGlev(key.columns.as_slice()).mul_crt_polynomial_to(
                &CrtPolynomial(&*coefficient),
                &mut DcrtGlwe(output.as_mut()),
                &p.basis,
                context.table(),
                context.codec(key.level).base_q(),
                workspace,
            );
        }
        (NativeEvaluationBasis::Hybrid(_), NativeProductWorkspace::Hybrid(product)) => {
            product.product_to(coefficient, &key.columns, output.as_mut());
        }
        _ => unreachable!("prepared native BFV workspace backend"),
    }
}

impl<'a> NativeGadgetProduct<'a> {
    fn try_new(
        context: &'a BfvContext,
        key: &'a NativeEvaluationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        key.validate(context)?;
        Ok(Self {
            context,
            key,
            coefficient: vec![0; context.rns_poly_len(key.level)],
            workspace: NativeProductWorkspace::try_new(context, key)?,
        })
    }
    fn poly_len(&self) -> usize {
        self.coefficient.len()
    }
    fn product_to<B: DataMut<Elem = u64>>(
        &mut self,
        input: &[u64],
        permutation: Option<&NttAutomorphismPermutation>,
        output: &mut BfvCiphertext<B>,
    ) {
        native_product_to(
            self.context,
            self.key,
            &mut self.coefficient,
            &mut self.workspace,
            input,
            permutation,
            output,
        );
    }
}

/// Reusable s²-to-s relinearization at one BFV prefix level.
pub struct BfvRelinearizer<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BfvRelinearizer<'a> {
    /// Binds the key's level and numerical metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects an unprepared key level or different N, t or ordered Q basis.
    pub fn try_new(
        context: &'a BfvContext,
        key: &'a BfvRelinearizationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
        })
    }

    /// Writes `[t0+P0,t1+P1]` for P encrypting t2*s².
    ///
    /// The input has already undergone BFV scale-and-round. A computation-only
    /// raw tensor is private to the multiplier and cannot be supplied here.
    ///
    /// # Correctness
    /// Input components are canonical residues using this actual secret,
    /// ordered level basis and NTT convention.
    /// Decomposition residual, key noise and Hybrid ModDown rounding consume
    /// the BFV phase-error margin;
    /// the complete evaluated error must satisfy the level codec recovery bound.
    /// # Panics
    /// Rejects incomplete input/output lengths before writes. Prepared calls
    /// allocate nothing; transform/RNS failure may partially overwrite scratch/output.
    pub fn relinearize_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvQuadraticCiphertext<A>,
        output: &mut BfvCiphertext<B>,
    ) {
        let len = self.product.poly_len();
        assert_eq!(
            input.as_ref().len(),
            3 * len,
            "BFV quadratic length mismatch"
        );
        assert_eq!(output.as_ref().len(), 2 * len, "BFV output length mismatch");
        let (t0, t1, t2) = input.c0_c1_c2(len);
        self.product.product_to(t2.as_ref(), None, output);
        let (mut c0, mut c1) = output.c0_c1_mut(len);
        let n = self.product.context.parameters().poly_length().get();
        let moduli = self
            .product
            .context
            .codec(self.product.key.level)
            .base_q()
            .moduli();
        c0.add_assign(&t0, n, moduli);
        c1.add_assign(&t1, n, moduli);
    }
}

/// Reusable switch from a designated source secret to the target secret.
pub struct BfvKeySwitcher<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BfvKeySwitcher<'a> {
    /// Binds the key's level and numerical metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects an unprepared key level or different N, t or ordered Q basis.
    pub fn try_new(
        context: &'a BfvContext,
        key: &'a BfvKeySwitchingKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
        })
    }

    /// Writes a native ciphertext under the key's actual target secret.
    ///
    /// # Correctness
    /// Input components are canonical residues using the key's actual source
    /// secret and the bound ordered Q/NTT convention. The complete evaluated
    /// error must satisfy the level codec recovery bound.
    /// # Panics
    /// Rejects incomplete input/output lengths before writes. Prepared calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn switch_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut BfvCiphertext<B>,
    ) {
        let len = self.product.poly_len();
        assert_eq!(input.as_ref().len(), 2 * len, "BFV input length mismatch");
        assert_eq!(output.as_ref().len(), 2 * len, "BFV output length mismatch");
        let (c0, c1) = input.c0_c1(len);
        self.product.product_to(c1.as_ref(), None, output);
        let (mut out0, _) = output.c0_c1_mut(len);
        out0.add_assign(
            &c0,
            self.product.context.parameters().poly_length().get(),
            self.product
                .context
                .codec(self.product.key.level)
                .base_q()
                .moduli(),
        );
    }
}

/// Reusable X -> X^k transformation and unscaled switch back to s.
pub struct BfvAutomorphism<'a> {
    product: NativeGadgetProduct<'a>,
    permutation: &'a NttAutomorphismPermutation,
}

impl<'a> BfvAutomorphism<'a> {
    /// Binds the key's level, numerical metadata and permutation before allocating scratch.
    /// # Errors
    /// Rejects an unprepared key level or different N, t or ordered Q basis.
    pub fn try_new(
        context: &'a BfvContext,
        key: &'a BfvAutomorphismKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
            permutation: &key.permutation,
        })
    }

    /// Writes σ(input) under the original secret, including the key-switch error.
    ///
    /// # Correctness
    /// Input components are canonical residues using the key's actual secret
    /// and the bound ordered Q/NTT convention.
    /// The complete evaluated error must satisfy the level codec bound. This
    /// operates on the full ciphertext ring; batching row maps choose the
    /// appropriate exponent.
    /// # Panics
    /// Rejects incomplete input/output lengths before writes. Prepared calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn apply_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BfvCiphertext<A>,
        output: &mut BfvCiphertext<B>,
    ) {
        let len = self.product.poly_len();
        assert_eq!(input.as_ref().len(), 2 * len, "BFV input length mismatch");
        assert_eq!(output.as_ref().len(), 2 * len, "BFV output length mismatch");
        let (c0, c1) = input.c0_c1(len);
        self.product
            .product_to(c1.as_ref(), Some(self.permutation), output);
        let n = self.product.context.parameters().poly_length().get();
        for (input, scratch) in c0
            .as_ref()
            .chunks_exact(n)
            .zip(self.product.coefficient.chunks_exact_mut(n))
        {
            self.permutation.apply_to(input, scratch);
        }
        let (mut out0, _) = output.c0_c1_mut(len);
        out0.add_assign(
            &DcrtPolynomial(self.product.coefficient.as_slice()),
            n,
            self.product
                .context
                .codec(self.product.key.level)
                .base_q()
                .moduli(),
        );
    }
}

fn validate_level(context: &BfvContext, level: usize) -> Result<(), BfvEvaluationKeyError> {
    if level >= context.level_count() {
        Err(BfvEvaluationKeyError::Level {
            requested: level,
            available: context.level_count(),
        })
    } else {
        Ok(())
    }
}

fn validate_numeric_context(
    n: usize,
    t: u64,
    moduli: &[u64],
    context: &BfvContext,
    level: usize,
) -> Result<(), BfvEvaluationKeyError> {
    let actual_n = context.parameters().poly_length().get();
    if n != actual_n {
        return Err(BfvEvaluationKeyError::PolynomialLength {
            expected: n,
            actual: actual_n,
        });
    }
    let actual_t = context.parameters().codec().t();
    if t != actual_t {
        return Err(BfvEvaluationKeyError::PlainModulus {
            expected: t,
            actual: actual_t,
        });
    }
    let actual_moduli = context.codec(level).base_q().moduli_values();
    if moduli.len() != actual_moduli.len() {
        return Err(BfvEvaluationKeyError::ModuliCount {
            expected: moduli.len(),
            actual: actual_moduli.len(),
        });
    }
    for (index, (&expected, &actual)) in moduli.iter().zip(actual_moduli).enumerate() {
        if expected != actual {
            return Err(BfvEvaluationKeyError::Modulus {
                index,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

mod collective;
pub use collective::*;
