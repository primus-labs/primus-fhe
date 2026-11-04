//! Scheme-owned p-preserving gadget keys in native `[c0,c1]` order.

use crate::{BgvCiphertext, BgvClient, BgvContext, BgvQuadraticCiphertext};
use primus_data::{Data, DataMut};
use primus_decompose::{
    ApproxSignedBasisError, DecompositionConfig, big_integer::BigUintApproxSignedBasis,
};
use primus_lattice::{
    GlweSizeError, RnsGadgetSize, RnsGlweSize, glev::DcrtGlev, glwe::DcrtGlwe,
    workspace::DcrtGlevMulWorkspace,
};
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::{ReduceInv, ReduceMul};
use primus_rns::Residues;
use zeroize::Zeroizing;

/// Invalid BGV evaluation-key parameters or numerical binding.
#[derive(Debug, thiserror::Error)]
pub enum BgvEvaluationKeyError {
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
    /// Complete evaluation-key storage would overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
}

/// One native BGV gadget's actual basis, layout and public evaluation columns.
/// The RNS base and transform table remain borrowed from the context.
struct NativeEvaluationKey {
    level: usize,
    p: u64,
    moduli: Vec<u64>,
    size: RnsGadgetSize,
    basis: BigUintApproxSignedBasis<u64>,
    columns: Vec<u64>,
}

impl NativeEvaluationKey {
    fn prepare(
        context: &BgvContext,
        level: usize,
        config: DecompositionConfig,
    ) -> Result<Self, BgvEvaluationKeyError> {
        let mut key = Self::prepare_metadata(context, level, config)?;
        key.columns = vec![0; key.size.rns_glev_len()];
        Ok(key)
    }

    fn prepare_metadata(
        context: &BgvContext,
        level: usize,
        config: DecompositionConfig,
    ) -> Result<Self, BgvEvaluationKeyError> {
        validate_level(context, level)?;
        let base = context.base_q(level);
        let basis = BigUintApproxSignedBasis::try_new(
            base.moduli_product(),
            config.log_basis,
            config.level_count,
        )?;
        for q in base.moduli() {
            if basis.basis_value() >= q.value() {
                return Err(BgvEvaluationKeyError::Radix {
                    radix: basis.basis_value(),
                    modulus: q.value(),
                });
            }
        }
        let size = RnsGadgetSize::try_new(
            RnsGlweSize::try_new(context.parameters().size().glwe_size(), base.moduli_count())?,
            basis.level_count(),
        )?;
        Ok(Self {
            level,
            p: context.parameters().plain_modulus().value(),
            moduli: base.moduli_values().to_vec(),
            size,
            basis,
            columns: Vec::new(),
        })
    }

    /// Native private encryption supplies p*e; only c0 receives p*g_j*h.
    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        mut self,
        client: &BgvClient<'_>,
        source: &[u64],
        rng: &mut R,
    ) -> Self {
        let context = client.context;
        let n = context.parameters().poly_length().get();
        let base = context.base_q(self.level);
        let poly_len = context.rns_poly_len(self.level);
        let mut weights = vec![0; base.moduli_count()];
        for (scalar, column) in self
            .basis
            .scalar_iter()
            .zip(self.columns.chunks_exact_mut(2 * poly_len))
        {
            base.decompose_to(primus_integer::BigUint(scalar), Residues(&mut weights));
            for (weight, q) in weights.iter_mut().zip(base.moduli()) {
                *weight = q.reduce_mul(*weight, self.p);
            }
            let mut output = BgvCiphertext::new(column);
            client.encrypt_zeros_at_level_to(&mut output, self.level, rng);
            let (mut c0, _) = output.c0_c1_mut(poly_len);
            c0.add_mul_scalar_assign(&DcrtPolynomial(source), &weights, n, base.moduli());
        }
        self
    }

    fn validate(&self, context: &BgvContext) -> Result<(), BgvEvaluationKeyError> {
        let level = self.level;
        validate_level(context, level)?;
        validate_numeric_context(
            self.size.rns_glwe_size().poly_length().get(),
            self.p,
            &self.moduli,
            context,
            level,
        )
    }

    #[cfg(test)]
    fn ciphertexts(&self) -> impl ExactSizeIterator<Item = BgvCiphertext<&[u64]>> {
        self.columns
            .chunks_exact(self.size.rns_glwe_size().rns_glwe_len())
            .map(BgvCiphertext::new)
    }
}

/// Public p-scaled columns encrypting gadget multiples of s² under s.
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

/// Public p-scaled columns encrypting the source secret under a target secret.
pub struct BgvKeySwitchingKey {
    key: NativeEvaluationKey,
}

/// Public p-scaled columns encrypting σ(s) under s for one odd automorphism.
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
    /// Generates p*g_j*s²+p*e_j columns under this client's actual secret.
    ///
    /// Temporary secret-square storage is erased on return or unwind.
    /// # Errors
    /// Rejects unsupported levels, radix or digit counts before sampling.
    pub fn relinearization_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        config: DecompositionConfig,
        rng: &mut R,
    ) -> Result<BgvRelinearizationKey, BgvEvaluationKeyError> {
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let len = self.context.rns_poly_len(level);
        let secret = self
            .secret_key()
            .iter_dcrt_poly()
            .next()
            .expect("rank-one secret");
        let mut square = Zeroizing::new(secret.as_ref()[..len].to_vec());
        DcrtPolynomial(square.as_mut_slice()).mul_assign(
            &DcrtPolynomial(&secret.as_ref()[..len]),
            self.context.parameters().poly_length().get(),
            self.context.base_q(level).moduli(),
        );
        Ok(BgvRelinearizationKey {
            key: key.encrypt(self, &square, rng),
        })
    }

    /// Generates p*g_j*σ(s)+p*e_j columns for X -> X^exponent under s.
    ///
    /// Temporary transformed-secret storage is erased on return or unwind.
    /// # Errors
    /// Rejects invalid exponents, levels or decomposition before sampling.
    pub fn automorphism_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        exponent: usize,
        config: DecompositionConfig,
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
        let secret = self
            .secret_key()
            .iter_dcrt_poly()
            .next()
            .expect("rank-one secret");
        let mut transformed = Zeroizing::new(vec![0; self.context.rns_poly_len(level)]);
        for (input, output) in secret
            .as_ref()
            .chunks_exact(n)
            .zip(transformed.chunks_exact_mut(n))
        {
            permutation.apply_to(input, output);
        }
        Ok(BgvAutomorphismKey {
            key: key.encrypt(self, &transformed, rng),
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
        config: DecompositionConfig,
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
        config: DecompositionConfig,
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
        config: DecompositionConfig,
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
        let key = NativeEvaluationKey::prepare(self.context, level, config)?;
        let secret = source
            .secret_key()
            .iter_dcrt_poly()
            .next()
            .expect("rank-one secret");
        Ok(BgvKeySwitchingKey {
            key: key.encrypt(
                self,
                &secret.as_ref()[..self.context.rns_poly_len(level)],
                rng,
            ),
        })
    }
}

/// Prepared native p-preserving product. The low-level GLev kernel is only a
/// componentwise linear sum: its temporary views do not invoke raw b-a*s phase,
/// mask/body combination, or a ciphertext sign conversion.
struct NativeGadgetProduct<'a> {
    context: &'a BgvContext,
    key: &'a NativeEvaluationKey,
    p_inverse: Vec<u64>,
    coefficient: Vec<u64>,
    workspace: DcrtGlevMulWorkspace<u64>,
}

impl<'a> NativeGadgetProduct<'a> {
    fn try_new(
        context: &'a BgvContext,
        key: &'a NativeEvaluationKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        key.validate(context)?;
        let level = key.level;
        let base = context.base_q(level);
        Ok(Self {
            context,
            key,
            p_inverse: base.moduli().iter().map(|q| q.reduce_inv(key.p)).collect(),
            coefficient: vec![0; context.rns_poly_len(level)],
            workspace: DcrtGlevMulWorkspace::new(key.size, base),
        })
    }

    fn poly_len(&self) -> usize {
        self.coefficient.len()
    }

    /// Established caller layouts precede this private kernel's first write.
    fn product_to<B: DataMut<Elem = u64>>(
        &mut self,
        input: &[u64],
        permutation: Option<&NttAutomorphismPermutation>,
        output: &mut BgvCiphertext<B>,
    ) {
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
        let base = self.context.base_q(self.key.level);
        DcrtPolynomial(self.coefficient.as_mut_slice()).mul_scalar_assign(
            &self.p_inverse,
            n,
            base.moduli(),
        );
        for (table, limb) in self
            .context
            .table()
            .ntt_tables()
            .iter()
            .zip(self.coefficient.chunks_exact_mut(n))
        {
            table.inverse_transform_slice(limb);
        }
        DcrtGlev(self.key.columns.as_slice()).mul_crt_polynomial_to(
            &CrtPolynomial(self.coefficient.as_slice()),
            &mut DcrtGlwe(output.as_mut()),
            &self.key.basis,
            self.context.table(),
            base,
            &mut self.workspace,
        );
    }
}

/// Reusable s²-to-s relinearization at one BGV prefix level.
pub struct BgvRelinearizer<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BgvRelinearizer<'a> {
    /// Binds the key's level and numerical metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects an unprepared key level or different N, p or ordered Q basis.
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
    /// Both decomposition residual and key noise contribute p-scaled error;
    /// the intended output phase must stay in the centered Q interval.
    /// # Panics
    /// Rejects incomplete input/output lengths before writes. Prepared calls
    /// allocate nothing; transform/RNS failure may partially overwrite scratch/output.
    pub fn relinearize_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvQuadraticCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
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
    /// Binds the key's level and numerical metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects an unprepared key level or different N, p or ordered Q basis.
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
    /// Rejects incomplete input/output lengths before writes. Prepared calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn switch_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
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
    /// Binds the key's level, numerical metadata and permutation before allocating scratch.
    /// # Errors
    /// Rejects an unprepared key level or different N, p or ordered Q basis.
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
    /// Rejects incomplete input/output lengths before writes. Prepared calls
    /// allocate nothing; arithmetic failure may partially overwrite scratch/output.
    pub fn apply_to<A: Data<Elem = u64>, B: DataMut<Elem = u64>>(
        &mut self,
        input: &BgvCiphertext<A>,
        output: &mut BgvCiphertext<B>,
    ) {
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

fn validate_level(context: &BgvContext, level: usize) -> Result<(), BgvEvaluationKeyError> {
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
