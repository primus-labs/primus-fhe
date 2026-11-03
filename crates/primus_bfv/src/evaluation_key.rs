//! Scheme-owned unscaled gadget keys in native `[c0,c1]` order.

use crate::{BfvCiphertext, BfvClient, BfvContext, BfvQuadraticCiphertext};
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
use primus_rns::Residues;
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
    /// A key was generated for a different level index.
    #[error("BFV key level mismatch: expected {expected}, got {actual}")]
    KeyLevel {
        /// Bound key level.
        expected: usize,
        /// Requested evaluator level.
        actual: usize,
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
    /// Complete evaluation-key storage would overflow.
    #[error(transparent)]
    Layout(#[from] GlweSizeError),
}

/// One native BFV gadget's actual basis, layout and public evaluation columns.
/// The RNS base and transform table remain borrowed from the context.
struct NativeEvaluationKey {
    level: usize,
    t: u64,
    moduli: Vec<u64>,
    size: RnsGadgetSize,
    basis: BigUintApproxSignedBasis<u64>,
    columns: Vec<u64>,
}

impl NativeEvaluationKey {
    fn prepare(
        context: &BfvContext,
        level: usize,
        config: DecompositionConfig,
    ) -> Result<Self, BfvEvaluationKeyError> {
        validate_level(context, level)?;
        let base = context.codec(level).base_q();
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
            RnsGlweSize::try_new(context.parameters().size().glwe_size(), base.moduli_count())?,
            basis.level_count(),
        )?;
        Ok(Self {
            level,
            t: context.parameters().codec().t(),
            moduli: base.moduli_values().to_vec(),
            size,
            basis,
            columns: vec![0; size.rns_glev_len()],
        })
    }

    /// Native private encryption supplies e; only c0 receives unscaled g_j*h.
    fn encrypt<R: rand::Rng + rand::CryptoRng>(
        mut self,
        client: &BfvClient<'_>,
        source: &[u64],
        rng: &mut R,
    ) -> Self {
        let context = client.context;
        let n = context.parameters().poly_length().get();
        let base = context.codec(self.level).base_q();
        let poly_len = context.rns_poly_len(self.level);
        let mut weights = vec![0; base.moduli_count()];
        for (scalar, column) in self
            .basis
            .scalar_iter()
            .zip(self.columns.chunks_exact_mut(2 * poly_len))
        {
            base.decompose_to(primus_integer::BigUint(scalar), Residues(&mut weights));
            let mut output = BfvCiphertext::new(column);
            client.encrypt_zeros_at_level_to(&mut output, self.level, rng);
            let (mut c0, _) = output.c0_c1_mut(poly_len);
            c0.add_mul_scalar_assign(&DcrtPolynomial(source), &weights, n, base.moduli());
        }
        self
    }

    fn validate(&self, context: &BfvContext, level: usize) -> Result<(), BfvEvaluationKeyError> {
        validate_level(context, level)?;
        if self.level != level {
            return Err(BfvEvaluationKeyError::KeyLevel {
                expected: self.level,
                actual: level,
            });
        }
        validate_numeric_context(
            self.size.rns_glwe_size().poly_length().get(),
            self.t,
            &self.moduli,
            context,
            level,
        )
    }

    fn ciphertexts(&self) -> impl ExactSizeIterator<Item = BfvCiphertext<&[u64]>> {
        self.columns
            .chunks_exact(self.size.rns_glwe_size().rns_glwe_len())
            .map(BfvCiphertext::new)
    }
}

/// Public unscaled columns encrypting gadget multiples of s² under s.
/// Construction reveals correlated evaluation keys; their security assumption
/// is additional to the fresh-ciphertext RLWE assumption.
pub struct BfvRelinearizationKey {
    key: NativeEvaluationKey,
}

impl BfvRelinearizationKey {
    /// Returns the level for which these columns were generated.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Returns the actual signed decomposition and its circular residual bound.
    #[must_use]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<u64> {
        &self.key.basis
    }

    /// Borrows native public columns in increasing retained decomposition order.
    pub fn ciphertexts(&self) -> impl ExactSizeIterator<Item = BfvCiphertext<&[u64]>> {
        self.key.ciphertexts()
    }
}

/// Public unscaled columns encrypting the source secret under a target secret.
pub struct BfvKeySwitchingKey {
    key: NativeEvaluationKey,
}

impl BfvKeySwitchingKey {
    /// Returns the level for which these columns were generated.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Returns the actual signed decomposition and its circular residual bound.
    #[must_use]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<u64> {
        &self.key.basis
    }

    /// Borrows native public columns in increasing retained decomposition order.
    pub fn ciphertexts(&self) -> impl ExactSizeIterator<Item = BfvCiphertext<&[u64]>> {
        self.key.ciphertexts()
    }
}

/// Public unscaled columns encrypting σ(s) under s for one odd automorphism.
pub struct BfvAutomorphismKey {
    key: NativeEvaluationKey,
    exponent: usize,
    permutation: NttAutomorphismPermutation,
}

impl BfvAutomorphismKey {
    /// Returns the level for which these columns were generated.
    #[must_use]
    pub fn level(&self) -> usize {
        self.key.level
    }

    /// Returns k for the substitution X -> X^k.
    #[must_use]
    pub fn exponent(&self) -> usize {
        self.exponent
    }

    /// Returns the actual signed decomposition and its circular residual bound.
    #[must_use]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<u64> {
        &self.key.basis
    }

    /// Borrows native public columns in increasing retained decomposition order.
    pub fn ciphertexts(&self) -> impl ExactSizeIterator<Item = BfvCiphertext<&[u64]>> {
        self.key.ciphertexts()
    }
}

impl BfvClient<'_> {
    /// Generates g_j*s²+e_j columns under this client's actual secret.
    ///
    /// Temporary secret-square storage is erased on return or unwind.
    /// # Errors
    /// Rejects unsupported levels, radix or digit counts before sampling.
    pub fn relinearization_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        level: usize,
        config: DecompositionConfig,
        rng: &mut R,
    ) -> Result<BfvRelinearizationKey, BfvEvaluationKeyError> {
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
            self.context.codec(level).base_q().moduli(),
        );
        Ok(BfvRelinearizationKey {
            key: key.encrypt(self, &square, rng),
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
        config: DecompositionConfig,
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
        Ok(BfvAutomorphismKey {
            key: key.encrypt(self, &transformed, rng),
            exponent,
            permutation,
        })
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
        config: DecompositionConfig,
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
        let secret = source
            .secret_key()
            .iter_dcrt_poly()
            .next()
            .expect("rank-one secret");
        Ok(BfvKeySwitchingKey {
            key: key.encrypt(
                self,
                &secret.as_ref()[..self.context.rns_poly_len(level)],
                rng,
            ),
        })
    }
}

/// Prepared native unscaled product. The low-level GLev kernel is only a
/// componentwise linear sum: its temporary views do not invoke raw b-a*s phase,
/// mask/body combination, or a ciphertext sign conversion.
struct NativeGadgetProduct<'a> {
    context: &'a BfvContext,
    key: &'a NativeEvaluationKey,
    coefficient: Vec<u64>,
    workspace: DcrtGlevMulWorkspace<u64>,
}

impl<'a> NativeGadgetProduct<'a> {
    fn try_new(
        context: &'a BfvContext,
        level: usize,
        key: &'a NativeEvaluationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        key.validate(context, level)?;
        let base = context.codec(level).base_q();
        Ok(Self {
            context,
            key,
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
        output: &mut BfvCiphertext<B>,
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
        let base = self.context.codec(self.key.level).base_q();
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

/// Reusable s²-to-s relinearization at one BFV prefix level.
pub struct BfvRelinearizer<'a> {
    product: NativeGadgetProduct<'a>,
}

impl<'a> BfvRelinearizer<'a> {
    /// Binds actual key metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects a different level, N, t or ordered Q basis.
    pub fn try_new(
        context: &'a BfvContext,
        level: usize,
        key: &'a BfvRelinearizationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, level, &key.key)?,
        })
    }

    /// Writes `[t0+P0,t1+P1]` for P encrypting t2*s².
    ///
    /// The input has already undergone BFV scale-and-round. A computation-only
    /// raw tensor has a distinct type and cannot be supplied here.
    ///
    /// ```compile_fail
    /// use primus_bfv::{BfvCiphertext, BfvRawTensor, BfvRelinearizer};
    /// fn premature_relin(
    ///     relin: &mut BfvRelinearizer<'_>,
    ///     raw: &BfvRawTensor,
    ///     output: &mut BfvCiphertext<Vec<u64>>,
    /// ) {
    ///     relin.relinearize_to(raw, output);
    /// }
    /// ```
    ///
    /// # Correctness
    /// Input components are canonical residues using this actual secret,
    /// ordered level basis and NTT convention.
    /// Decomposition residual and key noise consume the BFV phase-error margin;
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
    /// Binds actual key metadata before allocating reusable scratch.
    /// # Errors
    /// Rejects a different level, N, t or ordered Q basis.
    pub fn try_new(
        context: &'a BfvContext,
        level: usize,
        key: &'a BfvKeySwitchingKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, level, &key.key)?,
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
    /// Binds actual key metadata and its permutation before allocating scratch.
    /// # Errors
    /// Rejects a different level, N, t or ordered Q basis.
    pub fn try_new(
        context: &'a BfvContext,
        level: usize,
        key: &'a BfvAutomorphismKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        Ok(Self {
            product: NativeGadgetProduct::try_new(context, level, &key.key)?,
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
