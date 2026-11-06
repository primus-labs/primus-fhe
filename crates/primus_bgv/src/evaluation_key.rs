//! Scheme-owned p-preserving gadget keys in native `[c0,c1]` order.

use crate::{BgvCiphertext, BgvClient, BgvContext, BgvQuadraticCiphertext};
use primus_data::{Data, DataMut};
#[cfg(test)]
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_decompose::{ApproxSignedBasisError, DecompositionConfig};
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_glwe_rns::DcrtGlweSecretKey;
use primus_lattice::hybrid::{
    EvaluationKeyConfig, HybridModDown, NativeHybridError, NativeHybridParameters,
    NativeHybridProduct,
};
use primus_lattice::radix::{NativeRadixError, NativeRadixParameters};
use primus_lattice::{
    GlweSizeError, glev::DcrtGlev, glwe::DcrtGlwe, workspace::DcrtGlevMulWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::Reduce;
use primus_reduce::{ReduceInv, ReduceMul};
use primus_rns::RNSBase;
use std::sync::Arc;

/// Scheme key decomposition selection; radix and native Hybrid retain distinct error contracts.
pub use primus_lattice::hybrid::EvaluationKeyConfig as BgvEvaluationKeyConfig;
use zeroize::Zeroizing;

/// Invalid BGV evaluation-key parameters or numerical binding.
#[derive(Debug, thiserror::Error)]
pub enum BgvEvaluationKeyError {
    /// A native key or source client belongs to a different context owner.
    #[error("BGV evaluation key or source client belongs to another context")]
    ContextMismatch,
    /// A requested context level was not prepared.
    #[error("BGV key level {requested} is outside the {available} prepared levels")]
    Level {
        /// Requested level.
        requested: usize,
        /// Number of prepared levels.
        available: usize,
    },
    /// The full ciphertext polynomial length differs.
    #[error("BGV polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLength {
        /// Expected polynomial length.
        expected: usize,
        /// Supplied polynomial length.
        actual: usize,
    },
    /// The noise multiplier/plaintext modulus differs.
    #[error("BGV plaintext modulus mismatch: expected {expected}, got {actual}")]
    PlainModulus {
        /// Expected p.
        expected: u64,
        /// Supplied p.
        actual: u64,
    },
    /// A batching encoder's plaintext ring exceeds the full ciphertext ring.
    #[cfg(feature = "batching")]
    #[error("BGV slot capacity {actual} exceeds ciphertext ring length {maximum}")]
    SlotCapacity {
        /// Full ciphertext-ring length.
        maximum: usize,
        /// Encoder slot capacity.
        actual: usize,
    },
    /// Ordered Q bases have different lengths.
    #[error("BGV modulus count mismatch: expected {expected}, got {actual}")]
    ModuliCount {
        /// Expected retained modulus count.
        expected: usize,
        /// Supplied retained modulus count.
        actual: usize,
    },
    /// An ordered ciphertext modulus differs.
    #[error("BGV modulus mismatch at {index}: expected {expected}, got {actual}")]
    Modulus {
        /// Ordered modulus index.
        index: usize,
        /// Expected modulus.
        expected: u64,
        /// Supplied modulus.
        actual: u64,
    },
    /// Signed digit lifting needs B strictly below every retained prime.
    #[error("BGV gadget radix {radix} is not below ciphertext modulus {modulus}")]
    Radix {
        /// Gadget radix.
        radix: u64,
        /// Rejected retained modulus.
        modulus: u64,
    },
    /// An automorphism exponent must be odd and below 2N.
    #[error("BGV automorphism exponent {exponent} must be odd and below {twice_n}")]
    Exponent {
        /// Supplied exponent.
        exponent: usize,
        /// Exclusive upper bound.
        twice_n: usize,
    },
    /// The radix or retained digit count is incompatible with Q.
    #[error(transparent)]
    Decomposition(#[from] ApproxSignedBasisError),
    /// Native Hybrid basis, transform or geometry is unsupported.
    #[error(transparent)]
    Hybrid(#[from] NativeHybridError),
    /// A key modulus cannot carry the configured coherent integer error sample.
    #[error("BGV Hybrid noise magnitude {bound} is not below key modulus {modulus}")]
    NoiseSupport {
        /// Configured error support.
        bound: u64,
        /// Incompatible QP modulus.
        modulus: u64,
    },
    /// Complete evaluation-key storage would overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
}

impl From<NativeRadixError> for BgvEvaluationKeyError {
    fn from(error: NativeRadixError) -> Self {
        match error {
            NativeRadixError::Decomposition(error) => Self::Decomposition(error),
            NativeRadixError::Layout(error) => Self::Layout(error),
            NativeRadixError::Radix { radix, modulus } => Self::Radix { radix, modulus },
        }
    }
}

impl BgvContext {
    /// Prepares shared signed-radix metadata for role keys at one active Q level.
    /// The owner binds numerical geometry, not secret or NTT provenance.
    /// # Errors
    /// Rejects an unknown level, unsupported decomposition or overflowing shape.
    pub fn radix_key_parameters(
        &self,
        level: usize,
        config: DecompositionConfig,
    ) -> Result<Arc<NativeRadixParameters>, BgvEvaluationKeyError> {
        validate_level(self, level)?;
        Ok(Arc::new(NativeRadixParameters::try_new(
            self.parameters().poly_length(),
            self.base_q(level),
            config,
        )?))
    }
}

type KeyBase = RNSBase<u64, BarrettModulus<u64>>;

#[derive(Clone)]
enum KeyDecomposition {
    Radix(Arc<NativeRadixParameters>),
    Hybrid(Arc<NativeHybridParameters>),
}

/// Native key columns with exactly one chosen decomposition owner.
struct NativeEvaluationKey {
    context: Arc<()>,
    n: usize,
    level: usize,
    p: u64,
    moduli: Vec<u64>,
    decomposition: KeyDecomposition,
    columns: Vec<u64>,
}

impl NativeEvaluationKey {
    fn prepare(
        context: &BgvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
    ) -> Result<Self, BgvEvaluationKeyError> {
        let mut key = Self::prepare_metadata(context, level, config)?;
        key.columns.resize(key.key_len(context), 0);
        Ok(key)
    }

    fn prepare_metadata(
        context: &BgvContext,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
    ) -> Result<Self, BgvEvaluationKeyError> {
        validate_level(context, level)?;
        let base = context.base_q(level);
        let decomposition = match config.into() {
            EvaluationKeyConfig::Radix(config) => {
                KeyDecomposition::Radix(context.radix_key_parameters(level, config)?)
            }
            EvaluationKeyConfig::PreparedRadix(parameters) => {
                validate_numeric_context(
                    parameters.poly_length().get(),
                    context.parameters().plain_modulus().value(),
                    parameters.base_q().moduli_values(),
                    context,
                    level,
                )?;
                KeyDecomposition::Radix(parameters)
            }
            EvaluationKeyConfig::Hybrid(parameters) => {
                validate_numeric_context(
                    parameters.poly_length().get(),
                    context.parameters().plain_modulus().value(),
                    parameters.hybrid_rns().q_base().moduli_values(),
                    context,
                    level,
                )?;
                // This check is also performed when preparing the product, before
                // RNG consumption here, so unsupported t/P never creates a key.
                parameters.validate_mod_down(HybridModDown::PlaintextPreserving(
                    context.parameters().plain_modulus().value(),
                ))?;
                let sampling = context.parameters().encryption_parameters();
                let error_bound = sampling.noise_distribution().maximum_magnitude();
                for &q in parameters.hybrid_rns().qp_base().moduli_values() {
                    if error_bound >= q {
                        return Err(BgvEvaluationKeyError::NoiseSupport {
                            bound: error_bound,
                            modulus: q,
                        });
                    }
                }

                KeyDecomposition::Hybrid(parameters)
            }
        };
        Ok(Self {
            context: Arc::clone(context.identity()),
            n: context.parameters().poly_length().get(),
            level,
            p: context.parameters().plain_modulus().value(),
            moduli: base.moduli_values().to_vec(),
            decomposition,
            columns: Vec::new(),
        })
    }

    fn base<'a>(&'a self, context: &'a BgvContext) -> &'a KeyBase {
        match &self.decomposition {
            KeyDecomposition::Radix(_) => context.base_q(self.level),
            KeyDecomposition::Hybrid(p) => p.hybrid_rns().qp_base(),
        }
    }
    fn poly_len(&self, context: &BgvContext) -> usize {
        self.base(context).moduli_count() * context.parameters().poly_length().get()
    }
    fn digit_count(&self) -> usize {
        match &self.decomposition {
            KeyDecomposition::Radix(p) => p.basis().level_count().get(),
            KeyDecomposition::Hybrid(p) => p.partition_count(),
        }
    }
    fn key_len(&self, context: &BgvContext) -> usize {
        2 * self.poly_len(context) * self.digit_count()
    }
    fn is_hybrid(&self) -> bool {
        matches!(self.decomposition, KeyDecomposition::Hybrid(_))
    }
    fn weights(&self, index: usize) -> &[u64] {
        match &self.decomposition {
            KeyDecomposition::Radix(p) => p.key_weights(index),
            KeyDecomposition::Hybrid(p) => p.key_weights(index),
        }
    }
    fn transform(&self, context: &BgvContext, values: &mut [u64]) {
        match &self.decomposition {
            KeyDecomposition::Radix(_) => {
                context.table().transform_prefix_slice(values);
            }
            KeyDecomposition::Hybrid(p) => p.transform_qp_assign(context.table(), values),
        }
    }
    fn noise(&self, context: &BgvContext, output: &mut [u64], rng: &mut impl rand::CryptoRng) {
        context
            .parameters()
            .encryption_parameters()
            .sample_noise_to(output, self.base(context).moduli_values(), rng);
        if self.is_hybrid() {
            scale_with_p(
                self.p,
                context.parameters().poly_length().get(),
                self.base(context),
                output,
            );
        }
        self.transform(context, output);
    }
    fn uniform(&self, context: &BgvContext, output: &mut [u64], rng: &mut impl rand::CryptoRng) {
        if !self.is_hybrid() {
            let count = self.base(context).moduli_count();
            primus_distr::sample_crt_uniform_values_to(
                output,
                context.parameters().poly_length().get(),
                &context
                    .parameters()
                    .encryption_parameters()
                    .cipher_moduli_uniform_distr()[..count],
                rng,
            );
            return;
        }
        let distributions: Vec<_> = self
            .base(context)
            .moduli()
            .iter()
            .map(|q| rand::distr::Uniform::new(0, q.value()).expect("positive modulus"))
            .collect();
        primus_distr::sample_crt_uniform_values_to(
            output,
            context.parameters().poly_length().get(),
            &distributions,
            rng,
        );
    }
    fn secret(
        &self,
        context: &BgvContext,
        key: &DcrtGlweSecretKey<u64>,
    ) -> Result<Zeroizing<Vec<u64>>, BgvEvaluationKeyError> {
        let input = key.iter_dcrt_poly().next().expect("rank-one secret");
        match &self.decomposition {
            KeyDecomposition::Radix(_) => Ok(Zeroizing::new(
                input.as_ref()[..context.rns_poly_len(self.level)].to_vec(),
            )),
            KeyDecomposition::Hybrid(parameters) => Ok(parameters.extend_bounded_secret_to_qp(
                input.as_ref(),
                context.parameters().base_q(),
                context.table(),
                context
                    .parameters()
                    .encryption_parameters()
                    .secret_key_sampler()
                    .maximum_magnitude(),
            )?),
        }
    }

    fn encrypt(
        mut self,
        client: &BgvClient<'_>,
        source: &[u64],
        rng: &mut impl rand::CryptoRng,
    ) -> Result<Self, BgvEvaluationKeyError> {
        let context = client.context;
        let n = context.parameters().poly_length().get();
        let len = self.poly_len(context);
        let target = self.secret(client.context, client.secret_key())?;
        let base = self.base(context).clone();
        let mut weights = vec![0; base.moduli_count()];
        let mut columns = std::mem::take(&mut self.columns);
        for (digit, column) in columns.chunks_exact_mut(2 * len).enumerate() {
            weights.copy_from_slice(self.weights(digit));
            if !self.is_hybrid() {
                for (weight, q) in weights.iter_mut().zip(base.moduli()) {
                    *weight = q.reduce_mul(*weight, self.p);
                }
            }
            let (c0, c1) = column.split_at_mut(len);
            self.noise(context, c0, rng);
            if !self.is_hybrid() {
                scale_with_p(self.p, n, &base, c0);
            }
            self.uniform(context, c1, rng);
            DcrtPolynomial(&mut *c0).add_mul_scalar_assign(
                &DcrtPolynomial(source),
                &weights,
                n,
                base.moduli(),
            );
            DcrtPolynomial(c0).sub_mul_assign(
                &DcrtPolynomial(&*c1),
                &DcrtPolynomial(target.as_slice()),
                n,
                base.moduli(),
            );
        }
        self.columns = columns;
        Ok(self)
    }
    fn validate(&self, context: &BgvContext) -> Result<(), BgvEvaluationKeyError> {
        if Arc::ptr_eq(&self.context, context.identity()) {
            return Ok(());
        }
        validate_level(context, self.level)?;
        validate_numeric_context(self.n, self.p, &self.moduli, context, self.level)?;
        Err(BgvEvaluationKeyError::ContextMismatch)
    }
    fn clone_metadata(&self, columns: Vec<u64>) -> Self {
        Self {
            context: Arc::clone(&self.context),
            n: self.n,
            level: self.level,
            p: self.p,
            moduli: self.moduli.clone(),
            decomposition: self.decomposition.clone(),
            columns,
        }
    }
    #[cfg(test)]
    fn radix_basis(&self) -> &BigUintApproxSignedBasis<u64> {
        match &self.decomposition {
            KeyDecomposition::Radix(p) => p.basis(),
            _ => panic!("radix oracle requires radix key"),
        }
    }
    #[cfg(test)]
    fn ciphertexts(&self) -> impl ExactSizeIterator<Item = BgvCiphertext<&[u64]>> {
        let len = self.columns.len() / self.digit_count();
        self.columns.chunks_exact(len).map(BgvCiphertext::from_raw)
    }
}

fn scale_with_p(p: u64, n: usize, base: &KeyBase, values: &mut [u64]) {
    for (i, limb) in values.chunks_exact_mut(n).enumerate() {
        let q = base.moduli()[i % base.moduli_count()];
        // p may exceed an auxiliary prime. Prepare its canonical factor once
        // per limb, then use the native batch kernel for the complete limb.
        ShoupFactor::new(q.reduce(p), q.value()).factor_mul_slice_assign(limb, q.value());
    }
}

// Final key columns must be copied out of the authenticated sums. Fuse that
// copy with Radix p-scaling instead of reading and writing the column twice.
fn scale_with_p_to(p: u64, n: usize, base: &KeyBase, values: &[u64], output: &mut [u64]) {
    debug_assert_eq!(values.len(), output.len());
    for (i, (input, output)) in values
        .chunks_exact(n)
        .zip(output.chunks_exact_mut(n))
        .enumerate()
    {
        let q = base.moduli()[i % base.moduli_count()];
        ShoupFactor::new(q.reduce(p), q.value()).factor_mul_slice_to(input, output, q.value());
    }
}

/// Public native columns switching s² back to s. Radix encrypts p-scaled
/// gadget weights; Hybrid encrypts P times the actual CRT-projector weights.
/// Construction reveals correlated evaluation keys; their security assumption
/// is additional to the fresh-ciphertext RLWE assumption.
pub struct BgvRelinearizationKey {
    key: NativeEvaluationKey,
}

impl BgvRelinearizationKey {
    /// Returns the level for which these columns were generated.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }
}

/// Public native columns encrypting source-secret weights under a target secret.
/// The selected radix/Hybrid representation determines its Q or QP key domain.
pub struct BgvKeySwitchingKey {
    key: NativeEvaluationKey,
}

/// Public native columns switching σ(s) back to s for one odd automorphism.
pub struct BgvAutomorphismKey {
    key: NativeEvaluationKey,
    exponent: usize,
    permutation: NttAutomorphismPermutation,
}

impl BgvAutomorphismKey {
    /// Returns the native level (the number of removed tail primes).
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Returns the odd exponent in `X -> X^exponent`.
    #[must_use]
    pub fn exponent(&self) -> usize {
        self.exponent
    }
}

impl BgvClient<'_> {
    /// Generates native s²-to-s columns under the selected radix/Hybrid basis.
    ///
    /// Radix phases are p*g_j*s²+p*e_j in Q; Hybrid phases are
    /// P*projector_j*s²+p*e_j in QP. Key modulus/noise are caller budget inputs.
    ///
    /// Temporary secret-square storage is erased on return or unwind.
    /// # Errors
    /// Rejects unsupported levels, radix or digit counts before sampling.
    pub fn relinearization_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvRelinearizationKey, BgvEvaluationKeyError> {
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let secret = key.secret(self.context, self.secret_key())?;
        let mut square = Zeroizing::new(secret.to_vec());
        DcrtPolynomial(square.as_mut_slice()).mul_assign(
            &DcrtPolynomial(secret.as_slice()),
            self.context.parameters().poly_length().get(),
            key.base(self.context).moduli(),
        );
        Ok(BgvRelinearizationKey {
            key: key.encrypt(self, &square, rng)?,
        })
    }

    /// Generates native σ(s)-to-s columns for X -> X^exponent.
    /// The selected key representation follows [`Self::relinearization_key`].
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
    ) -> Result<BgvAutomorphismKey, BgvEvaluationKeyError> {
        let n = self.context.parameters().poly_length().get();
        if exponent >= 2 * n || exponent & 1 == 0 {
            return Err(BgvEvaluationKeyError::Exponent {
                exponent,
                twice_n: 2 * n,
            });
        }
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let permutation =
            NttAutomorphismPermutation::new(exponent, self.context.parameters().poly_length());
        let secret = key.secret(self.context, self.secret_key())?;
        let mut transformed = Zeroizing::new(vec![0; secret.len()]);
        for (input, output) in secret.chunks_exact(n).zip(transformed.chunks_exact_mut(n)) {
            permutation.apply_to(input, output);
        }
        Ok(BgvAutomorphismKey {
            key: key.encrypt(self, &transformed, rng)?,
            exponent,
            permutation,
        })
    }

    /// Generates a row-left rotation key using signed steps in the encoder's layout.
    ///
    /// Negative steps rotate right; steps wrap modulo half the encoder capacity.
    /// The encoder may use an n<N plaintext subring; the ciphertext and secret
    /// remain full N. This returns the existing automorphism key role.
    /// # Correctness
    /// The encoder's plaintext p must be prime, as required by its constructor.
    /// # Errors
    /// Rejects a different plaintext modulus or n>N before sampling, followed by
    /// [`Self::automorphism_key`]'s level and decomposition checks.
    #[cfg(feature = "batching")]
    pub fn row_rotation_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        steps: isize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvAutomorphismKey, BgvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.rotation_exponent(steps), config, rng)
    }

    /// Generates a key swapping the encoder's two rows without reversing them.
    ///
    /// The full-ring/subring, correctness and error contracts are
    /// [`Self::row_rotation_key`]'s; only the row permutation differs.
    #[cfg(feature = "batching")]
    pub fn row_swap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        encoder: &primus_encoding::BatchingEncoder,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvAutomorphismKey, BgvEvaluationKeyError> {
        self.validate_batching_encoder(encoder)?;
        self.automorphism_key(level, encoder.row_swap_exponent(), config, rng)
    }

    #[cfg(feature = "batching")]
    fn validate_batching_encoder(
        &self,
        encoder: &primus_encoding::BatchingEncoder,
    ) -> Result<(), BgvEvaluationKeyError> {
        let parameters = self.context.parameters();
        let expected = parameters.plain_modulus().value();
        let actual = encoder.plain_modulus();
        if expected != actual {
            return Err(BgvEvaluationKeyError::PlainModulus { expected, actual });
        }
        let maximum = parameters.poly_length().get();
        let actual = encoder.slot_capacity();
        if actual > maximum {
            return Err(BgvEvaluationKeyError::SlotCapacity { maximum, actual });
        }
        Ok(())
    }

    /// Generates a key switching source ciphertexts to this client's secret.
    ///
    /// # Correctness
    /// The callers maintain the intended source/target secret identities and
    /// matching NTT representation. Numeric equality does not establish identity.
    /// # Errors
    /// Rejects different N, p, ordered level bases or decomposition before sampling.
    pub fn key_switching_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        source: &BgvClient<'_>,
        level: usize,
        config: impl Into<EvaluationKeyConfig>,
        rng: &mut R,
    ) -> Result<BgvKeySwitchingKey, BgvEvaluationKeyError> {
        validate_level(self.context, level)?;
        validate_level(source.context, level)?;
        validate_numeric_context(
            self.context.parameters().poly_length().get(),
            self.context.parameters().plain_modulus().value(),
            self.context.base_q(level).moduli_values(),
            source.context,
            level,
        )?;
        if !Arc::ptr_eq(self.context.identity(), source.context.identity()) {
            return Err(BgvEvaluationKeyError::ContextMismatch);
        }
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let secret = key.secret(source.context, source.secret_key())?;
        Ok(BgvKeySwitchingKey {
            key: key.encrypt(self, &secret, rng)?,
        })
    }
}

/// Prepared native p-preserving product. The low-level GLev kernel is only a
/// componentwise linear sum: its temporary views do not invoke raw b-a*s phase,
/// mask/body combination, or a ciphertext sign conversion.
enum ProductWorkspace<'a> {
    Radix {
        p_inverse: Vec<u64>,
        workspace: DcrtGlevMulWorkspace<u64>,
    },
    Hybrid(NativeHybridProduct<'a>),
}
struct NativeGadgetProduct<'a> {
    context: &'a BgvContext,
    key: &'a NativeEvaluationKey,
    coefficient: Vec<u64>,
    workspace: ProductWorkspace<'a>,
}
impl<'a> NativeGadgetProduct<'a> {
    fn try_new(
        context: &'a BgvContext,
        key: &'a NativeEvaluationKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        key.validate(context)?;
        let base = context.base_q(key.level);
        let workspace = match &key.decomposition {
            KeyDecomposition::Radix(p) => ProductWorkspace::Radix {
                p_inverse: base.moduli().iter().map(|q| q.reduce_inv(key.p)).collect(),
                workspace: DcrtGlevMulWorkspace::new(p.size(), base),
            },
            KeyDecomposition::Hybrid(parameters) => {
                ProductWorkspace::Hybrid(NativeHybridProduct::try_new(
                    parameters,
                    context.table(),
                    HybridModDown::PlaintextPreserving(key.p),
                )?)
            }
        };
        Ok(Self {
            context,
            key,
            coefficient: vec![0; context.rns_poly_len(key.level)],
            workspace,
        })
    }
    fn poly_len(&self) -> usize {
        self.coefficient.len()
    }
    fn product_to<B: DataMut<Elem = u64>>(
        &mut self,
        input: &[u64],
        permutation: Option<&NttAutomorphismPermutation>,
        output: &mut BgvCiphertext<B>,
    ) {
        if permutation.is_none()
            && let ProductWorkspace::Hybrid(product) = &mut self.workspace
        {
            product.product_to(input, &self.key.columns, output.as_mut());
            return;
        }
        let n = self.context.parameters().poly_length().get();
        if let Some(permutation) = permutation {
            for (input, output) in input
                .chunks_exact(n)
                .zip(self.coefficient.chunks_exact_mut(n))
            {
                permutation.apply_to(input, output);
            }
        } else {
            self.coefficient.copy_from_slice(input);
        }
        match &mut self.workspace {
            ProductWorkspace::Radix {
                p_inverse,
                workspace,
            } => {
                let base = self.context.base_q(self.key.level);
                DcrtPolynomial(self.coefficient.as_mut_slice()).mul_scalar_assign(
                    p_inverse,
                    n,
                    base.moduli(),
                );
                for (table, limb) in self
                    .context
                    .table()
                    .iter()
                    .zip(self.coefficient.chunks_exact_mut(n))
                {
                    table.inverse_transform_slice(limb);
                }
                let KeyDecomposition::Radix(p) = &self.key.decomposition else {
                    unreachable!("bound radix workspace")
                };
                DcrtGlev(self.key.columns.as_slice()).mul_crt_polynomial_to(
                    &CrtPolynomial(self.coefficient.as_slice()),
                    &mut DcrtGlwe(output.as_mut()),
                    p.basis(),
                    self.context.table(),
                    base,
                    workspace,
                );
            }
            ProductWorkspace::Hybrid(product) => {
                product.product_to(&self.coefficient, &self.key.columns, output.as_mut())
            }
        }
    }
}

/// Reusable s²-to-s relinearization at one BGV prefix level.
pub struct BgvRelinearizer<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BgvRelinearizer<'a> {
    /// Checks the key's exact context and level before allocating reusable scratch.
    /// # Errors
    /// Rejects a foreign context, unprepared key level or different N, p or ordered Q.
    pub fn try_new(
        context: &'a BgvContext,
        key: &'a BgvRelinearizationKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
        })
    }

    /// Writes `[t0+P0,t1+P1]` for P encrypting t2*s².
    ///
    /// # Correctness
    /// Input components are canonical residues using this actual secret,
    /// ordered level basis and NTT convention.
    /// Radix residual/key noise or Hybrid key/ModDown corrections contribute
    /// p-scaled error;
    /// the intended output phase must stay in the centered Q interval.
    /// # Panics
    /// Rejects recorded context/level mismatches or incomplete lengths before writes. Calls
    /// allocate nothing; transform/RNS failure may partially overwrite scratch/output.
    pub fn relinearize_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvQuadraticCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
        input.check_binding(self.product.context, self.product.key.level);
        output.check_binding(self.product.context, self.product.key.level);
        let len = self.product.poly_len();
        assert_eq!(
            input.as_ref().len(),
            3 * len,
            "BGV quadratic length mismatch"
        );
        assert_eq!(output.as_ref().len(), 2 * len, "BGV output length mismatch");
        let (t0, t1, t2) = input.c0_c1_c2(len);
        self.product.product_to(t2.as_ref(), None, output);
        let (mut c0, mut c1) = output.c0_c1_mut(len);
        let n = self.product.context.parameters().poly_length().get();
        let moduli = self.product.context.base_q(self.product.key.level).moduli();
        c0.add_assign(&t0, n, moduli);
        c1.add_assign(&t1, n, moduli);
    }
}

/// Reusable switch from a designated source secret to the target secret.
pub struct BgvKeySwitcher<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BgvKeySwitcher<'a> {
    /// Checks the key's exact context and level before allocating reusable scratch.
    /// # Errors
    /// Rejects a foreign context, unprepared key level or different N, p or ordered Q.
    pub fn try_new(
        context: &'a BgvContext,
        key: &'a BgvKeySwitchingKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, &key.key)?,
        })
    }

    /// Writes a native ciphertext under the key's actual target secret.
    ///
    /// # Correctness
    /// Input components are canonical residues using the key's actual source
    /// secret and the bound ordered Q/NTT convention. The output's intended
    /// phase must stay inside centered Q.
    /// # Panics
    /// Rejects recorded context/level mismatches or incomplete lengths before writes. Calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn switch_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
        input.check_binding(self.product.context, self.product.key.level);
        output.check_binding(self.product.context, self.product.key.level);
        let len = self.product.poly_len();
        assert_eq!(input.as_ref().len(), 2 * len, "BGV input length mismatch");
        assert_eq!(output.as_ref().len(), 2 * len, "BGV output length mismatch");
        let (c0, c1) = input.c0_c1(len);
        self.product.product_to(c1.as_ref(), None, output);
        let (mut out0, _) = output.c0_c1_mut(len);
        out0.add_assign(
            &c0,
            self.product.context.parameters().poly_length().get(),
            self.product.context.base_q(self.product.key.level).moduli(),
        );
    }
}

/// Reusable X -> X^k transformation and p-preserving switch back to s.
pub struct BgvAutomorphism<'a> {
    product: NativeGadgetProduct<'a>,
    permutation: &'a NttAutomorphismPermutation,
}

impl<'a> BgvAutomorphism<'a> {
    /// Checks the key's exact context, level and permutation before allocating scratch.
    /// # Errors
    /// Rejects a foreign context, unprepared key level or different N, p or ordered Q.
    pub fn try_new(
        context: &'a BgvContext,
        key: &'a BgvAutomorphismKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
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
    /// The output's intended phase must stay in centered Q. This operates on the
    /// full ciphertext ring; batching row maps choose the appropriate exponent.
    /// # Panics
    /// Rejects recorded context/level mismatches or incomplete lengths before writes. Calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn apply_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
        input.check_binding(self.product.context, self.product.key.level);
        output.check_binding(self.product.context, self.product.key.level);
        let len = self.product.poly_len();
        assert_eq!(input.as_ref().len(), 2 * len, "BGV input length mismatch");
        assert_eq!(output.as_ref().len(), 2 * len, "BGV output length mismatch");
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
            self.product.context.base_q(self.product.key.level).moduli(),
        );
    }
}

pub(crate) fn validate_level(
    context: &BgvContext,
    level: usize,
) -> Result<(), BgvEvaluationKeyError> {
    if level >= context.level_count() {
        Err(BgvEvaluationKeyError::Level {
            requested: level,
            available: context.level_count(),
        })
    } else {
        Ok(())
    }
}

fn validate_numeric_context(
    n: usize,
    p: u64,
    moduli: &[u64],
    context: &BgvContext,
    level: usize,
) -> Result<(), BgvEvaluationKeyError> {
    let actual_n = context.parameters().poly_length().get();
    if n != actual_n {
        return Err(BgvEvaluationKeyError::PolynomialLength {
            expected: n,
            actual: actual_n,
        });
    }
    let actual_p = context.parameters().plain_modulus().value();
    if p != actual_p {
        return Err(BgvEvaluationKeyError::PlainModulus {
            expected: p,
            actual: actual_p,
        });
    }
    let actual_moduli = context.base_q(level).moduli_values();
    if moduli.len() != actual_moduli.len() {
        return Err(BgvEvaluationKeyError::ModuliCount {
            expected: moduli.len(),
            actual: actual_moduli.len(),
        });
    }
    for (index, (&expected, &actual)) in moduli.iter().zip(actual_moduli).enumerate() {
        if expected != actual {
            return Err(BgvEvaluationKeyError::Modulus {
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
