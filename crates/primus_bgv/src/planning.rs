//! Public, deterministic integer-phase budgets for ordinary static BGV circuits.

use crate::correction::{align, centered_abs, gcd, inverse, multiply};
use dashu_int::{UBig, ops::BitTest};
use primus_decompose::DecompositionConfig;
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    SecretKeyDistr,
    rlwe_parameters::{
        RlweParameterError, RlweSecurityInput, search_ntt_primes, security_input,
        validate_ntt_primes,
    },
};
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;

use crate::keys::{BgvEvaluationKeyConfig, BgvEvaluationKeyError};
use crate::{BgvContext, BgvContextError, BgvParameters, BgvParametersError, PlaintextEmbedding};

/// Arithmetic generation or a public circuit admission failed.
#[derive(Debug, thiserror::Error)]
pub enum BgvPlanningError {
    /// A supplied/generated basis is not a supported prime NTT basis.
    #[error(transparent)]
    Primes(#[from] RlweParameterError),
    /// Scheme parameters rejected the selected arithmetic/sampling law.
    #[error(transparent)]
    Parameters(#[from] BgvParametersError),
    /// The context cannot prepare the requested level inventory.
    #[error(transparent)]
    Context(#[from] BgvContextError),
    /// The ordinary key backend is incompatible with the actual level.
    #[error(transparent)]
    EvaluationKey(#[from] BgvEvaluationKeyError),
    /// A public plaintext or static operation violates its declared contract.
    #[error("BGV public circuit node {node}: {reason}")]
    Circuit {
        /// Zero-based operation index; zero also identifies request preparation.
        node: usize,
        /// Public explanation, containing no secret observation.
        reason: &'static str,
    },
    /// The complete intended integer phase does not fit centered Q.
    #[error(
        "BGV node {node} at level {level}: phase bound {phase_bound} exceeds centered capacity {capacity}; Q needs at least {required_modulus_bits} bits"
    )]
    Recovery {
        /// First rejected operation.
        node: usize,
        /// Actual prefix level of that operation.
        level: usize,
        /// Decimal public upper bound on the coefficient phase norm.
        phase_bound: String,
        /// Decimal floor(Q/2) at the rejected level.
        capacity: String,
        /// Necessary bit width for this sufficient bound; actual Q must exceed twice the bound.
        required_modulus_bits: usize,
    },
}

/// A bounded ordinary parameter-generation request, separate from circuit admission.
///
/// N, prime width/count and levels are explicit resource choices. Generation
/// finds actual primes, not an optimal Q or a security level. Adjust these
/// choices using a rejected circuit node's required-bit diagnostic.
pub struct BgvParameterRequest {
    /// Full coefficient polynomial length N, a supported power of two.
    pub poly_length: PolyLength,
    /// Coefficient plaintext modulus p; coefficient arithmetic permits composite p.
    pub plaintext_modulus: u64,
    /// Bit width of each generated ciphertext prime, below the native 62-bit limit.
    pub ciphertext_prime_bits: u32,
    /// Number of ordered top-level ciphertext primes.
    pub ciphertext_prime_count: usize,
    /// Number of prefix levels to prepare, including level zero.
    pub level_count: usize,
    /// Actual client secret distribution, also used for the target of ordinary switching.
    pub secret_distribution: SecretKeyDistr,
    /// Actual bounded error sampler, shared by ordinary encryption/key generation.
    pub error_distribution: ErrorDistribution,
}

impl BgvParameterRequest {
    /// Generates ordinary NTT primes, validates them and prepares one context.
    /// The ciphertext primes need not be one modulo the plaintext modulus.
    ///
    /// This establishes arithmetic compatibility and the constructor's fresh
    /// private recovery bound. Call [`BgvCircuitPlan::try_new`] for the complete
    /// declared public/evaluated circuit. Neither operation establishes RLWE security.
    pub fn create_context(&self) -> Result<BgvContext, BgvPlanningError> {
        let primes = search_ntt_primes(
            self.poly_length.get(),
            self.ciphertext_prime_bits,
            self.ciphertext_prime_count,
            None,
            &[],
        )?;
        let moduli = primes
            .into_iter()
            .map(BarrettModulus::new)
            .collect::<Vec<_>>();
        let parameters = BgvParameters::try_coefficients(
            self.poly_length,
            BarrettModulus::new(self.plaintext_modulus),
            &moduli,
            self.secret_distribution,
            self.error_distribution,
        )?;
        Ok(BgvContext::try_with_levels(parameters, self.level_count)?)
    }
}

/// Actual ordinary evaluation-key representation covered by a circuit budget.
#[derive(Clone)]
pub enum BgvBudgetBackend {
    /// Signed-radix Q keys, including their actual discarded-bit residual.
    Radix(DecompositionConfig),
    /// Partitioned QP keys; P is a key exposure modulus, not a data-level drop.
    Hybrid {
        /// Full-chain partition count, retaining the native fixed partition geometry.
        decomposition_count: usize,
        /// Actual ordered P primes, independently validated before preparation.
        auxiliary_moduli: Vec<u64>,
    },
}

impl BgvBudgetBackend {
    /// Generates ordinary Hybrid key P independently from the ciphertext Q chain.
    ///
    /// P needs NTT primes coprime to pQ; unlike Q it need not be 1 modulo p.
    /// The chosen width/count is explicit, and insufficient error capacity is
    /// reported by circuit admission. No security level follows from this choice.
    pub fn hybrid(
        context: &BgvContext,
        decomposition_count: usize,
        prime_bits: u32,
        prime_count: usize,
    ) -> Result<Self, BgvPlanningError> {
        let parameters = context.parameters();
        let p = parameters.plain_modulus().value();
        let mut exclude = parameters.base_q().moduli_values().to_vec();
        // A prime plaintext may otherwise collide with a generated P prime.
        exclude.push(p);
        loop {
            let auxiliary_moduli = search_ntt_primes(
                parameters.poly_length().get(),
                prime_bits,
                prime_count,
                None,
                &exclude,
            )?;
            let previous_exclusions = exclude.len();
            // Composite p is supported too. Each retry excludes a new prime
            // divisor of this u64 p, so there are finitely many retries without
            // factoring p or relaxing the bounded prime-search contract.
            exclude.extend(
                auxiliary_moduli
                    .iter()
                    .copied()
                    .filter(|&prime| gcd(prime, p) != 1),
            );
            if exclude.len() == previous_exclusions {
                return Ok(Self::Hybrid {
                    decomposition_count,
                    auxiliary_moduli,
                });
            }
        }
    }
}

/// Norms of one actual public coefficient polynomial under its selected lift.
///
/// Construct from the same public polynomial/embedding passed to evaluation.
/// Reusing this description for a larger polynomial is a caller contract;
/// ciphertext storage and this public planner cannot inspect encrypted messages.
#[derive(Clone, Debug)]
pub struct BgvPlaintextBounds {
    n: usize,
    p: u64,
    infinity: u64,
    one: UBig,
    embedding: PlaintextEmbedding,
}

impl BgvPlaintextBounds {
    /// Scans N canonical public coefficients once, rejecting wrong shape or values.
    pub fn try_new(
        poly_length: PolyLength,
        plain_modulus: BarrettModulus<u64>,
        coefficients: &[u64],
        embedding: PlaintextEmbedding,
    ) -> Result<Self, BgvPlanningError> {
        let n = poly_length.get();
        let p = plain_modulus.value();
        if p < 2 || coefficients.len() != n || coefficients.iter().any(|&x| x >= p) {
            return Err(BgvPlanningError::Circuit {
                node: 0,
                reason: "public plaintext must contain N canonical coefficients modulo p",
            });
        }
        let mut infinity = 0;
        let mut one = UBig::ZERO;
        for &value in coefficients {
            let magnitude = match embedding {
                PlaintextEmbedding::Unsigned => value,
                PlaintextEmbedding::Centered => value.min(p - value),
            };
            infinity = infinity.max(magnitude);
            one += magnitude;
        }
        Ok(Self {
            n,
            p,
            infinity,
            one,
            embedding,
        })
    }
}

/// One operation in a static, topologically ordered ordinary BGV circuit.
///
/// Operand indices refer to earlier operations. Binary operands must use the
/// same actual secret and level. Key switching changes the actual secret to a
/// target sampled from the context's stated law; all subsequent operations must
/// use that target consistently. These are semantic caller contracts, not a
/// secret-provenance proof. Multiplication includes ordinary relinearization.
#[derive(Clone, Debug)]
pub enum BgvCircuitOperation {
    /// A fresh ordinary public encryption of a full-range message at level zero.
    PublicEncryption {
        /// Actual message lift used by the public encryptor.
        embedding: PlaintextEmbedding,
    },
    /// A fresh private encryption of a full-range message at level zero.
    PrivateEncryption {
        /// Actual message lift used by the client.
        embedding: PlaintextEmbedding,
    },
    /// Adds two earlier degree-one results at the same level.
    Add {
        /// Earlier left operand.
        lhs: usize,
        /// Earlier right operand.
        rhs: usize,
    },
    /// Subtracts two earlier degree-one results with correction-factor alignment.
    Subtract {
        /// Earlier left operand.
        lhs: usize,
        /// Earlier right operand.
        rhs: usize,
    },
    /// Multiplies two earlier results and relinearizes at their actual level.
    Multiply {
        /// Earlier left operand; equal indices describe squaring.
        lhs: usize,
        /// Earlier right operand.
        rhs: usize,
    },
    /// Adds the specified public coefficient lift.
    AddPlain {
        /// Earlier ciphertext operand.
        input: usize,
        /// Norms of the actual public polynomial and embedding.
        plaintext: BgvPlaintextBounds,
    },
    /// Multiplies by the specified public coefficient lift.
    MultiplyPlain {
        /// Earlier ciphertext operand.
        input: usize,
        /// Norms of the actual public polynomial and embedding.
        plaintext: BgvPlaintextBounds,
    },
    /// Applies X->X^exponent and its ordinary automorphism key.
    Automorphism {
        /// Earlier ciphertext operand.
        input: usize,
        /// Odd exponent strictly below 2N.
        exponent: usize,
    },
    /// Switches to an ordinary target secret sampled from the same declared law.
    KeySwitch {
        /// Earlier ciphertext operand under the source secret.
        input: usize,
    },
    /// Drops the last Q prime and updates the message correction factor.
    DropPrime {
        /// Earlier degree-one ciphertext operand.
        input: usize,
    },
}

/// One explicit contribution to a node's deterministic integer phase bound.
#[derive(Clone, Debug)]
pub struct BgvBudgetTerm {
    /// Mathematical role of this nonnegative bound.
    pub label: &'static str,
    /// Absolute coefficient norm contribution; no statistical independence is assumed.
    pub bound: UBig,
}

/// Complete admission record of one operation at its actual level.
#[derive(Clone, Debug)]
pub struct BgvBudgetStep {
    /// Index of the corresponding public operation.
    pub node: usize,
    /// Prefix level, counting removed tail primes.
    pub level: usize,
    /// Canonical unit multiplying the logical message modulo p at this node.
    pub correction_factor: u64,
    /// Additive contributions whose sum is `phase_bound`.
    pub terms: Vec<BgvBudgetTerm>,
    /// Upper bound on the intended integer phase, including message carries.
    pub phase_bound: UBig,
    /// Error bound relative to the centered factor-encoded output message.
    /// This is floor((phase_bound+floor(p/2))/p), including message carry even
    /// if an input used unsigned lifting; logical recovery removes the factor.
    pub error_bound: UBig,
    /// Exact centered recovery capacity floor(Q/2).
    pub capacity: UBig,
    /// Nonnegative difference `capacity-phase_bound`.
    pub margin: UBig,
}

/// A public deterministic budget for one declared ordinary static circuit.
///
/// Tracks the full integer phase z, not just e in z=lift(factor*m)+p*e:
/// multiplication and plaintext operations retain message carries, while the
/// factor records the logical message scale after data-prime drops.
/// It uses hard sampler supports and full-ring convolution bounds, including
/// repeated/correlated inputs and keys. It can conservatively reject circuits
/// that would usually decrypt. It covers neither collective/raw/SSLE keys nor
/// privacy opening, unbounded programs or a statistical/security certificate.
/// Context and numeric tables remain owned by the borrowed context.
pub struct BgvCircuitPlan<'a> {
    context: &'a BgvContext,
    steps: Vec<BgvBudgetStep>,
    keys: Vec<Option<BgvEvaluationKeyConfig>>,
    security_inputs: Vec<RlweSecurityInput>,
}

impl<'a> BgvCircuitPlan<'a> {
    /// Validates all actual primes and admits each node with 2*||z||_infinity<Q.
    ///
    /// Fresh public encryption includes its fixed CBD1 ephemeral, independently
    /// of the context's secret law. All ordinary keys use the context's error law.
    /// Returned key configurations are the actual prepared per-level backends
    /// included in the ledger; pass them to role-key generation.
    pub fn try_new(
        context: &'a BgvContext,
        operations: &[BgvCircuitOperation],
        backend: BgvBudgetBackend,
    ) -> Result<Self, BgvPlanningError> {
        let parameters = context.parameters();
        let n = parameters.poly_length().get();
        let p = parameters.plain_modulus().value();
        let qs = parameters.base_q().moduli_values();
        validate_ntt_primes(n, qs)?;
        if let BgvBudgetBackend::Hybrid {
            auxiliary_moduli, ..
        } = &backend
        {
            validate_ntt_primes(n, auxiliary_moduli)?;
            if auxiliary_moduli
                .iter()
                .any(|q| qs.contains(q) || gcd(*q, p) != 1)
            {
                return Err(BgvPlanningError::Circuit {
                    node: 0,
                    reason: "Hybrid key P must be coprime to plaintext p and data Q",
                });
            }
        }
        if operations.is_empty() {
            return Err(BgvPlanningError::Circuit {
                node: 0,
                reason: "the declared circuit must contain at least one operation",
            });
        }
        let sampling = parameters.encryption_parameters();
        let e = UBig::from(sampling.noise_distribution().maximum_magnitude());
        let h = UBig::from(n) * sampling.secret_key_sampler().maximum_magnitude();
        let mut plan = Self {
            context,
            steps: Vec::with_capacity(operations.len()),
            keys: vec![None; context.level_count()],
            security_inputs: vec![security_input(sampling, qs, &[])?],
        };
        if operations
            .iter()
            .any(|operation| matches!(operation, BgvCircuitOperation::PublicEncryption { .. }))
        {
            plan.security_inputs[0].ephemeral_distribution = Some(SecretKeyDistr::SparseTernary);
        }
        for (node, operation) in operations.iter().enumerate() {
            let mut terms = Vec::new();
            let mut add = |label, bound| terms.push(BgvBudgetTerm { label, bound });
            let (level, correction_factor) = match operation {
                BgvCircuitOperation::PublicEncryption { embedding } => {
                    add("message lift", UBig::from(message_bound(p, *embedding)));
                    add(
                        "public-key error times CBD1 ephemeral",
                        UBig::from(n) * &e * p,
                    );
                    add("fresh body error", &e * p);
                    add("fresh mask error times secret", &h * &e * p);
                    (0, 1)
                }
                BgvCircuitOperation::PrivateEncryption { embedding } => {
                    add("message lift", UBig::from(message_bound(p, *embedding)));
                    add("fresh private error", &e * p);
                    (0, 1)
                }
                BgvCircuitOperation::Add { lhs, rhs }
                | BgvCircuitOperation::Subtract { lhs, rhs }
                | BgvCircuitOperation::Multiply { lhs, rhs } => {
                    let left = plan.operand(node, *lhs)?;
                    let right = plan.operand(node, *rhs)?;
                    if left.level != right.level {
                        return Err(BgvPlanningError::Circuit {
                            node,
                            reason: "binary operands must have the same actual level",
                        });
                    }
                    let level = left.level;
                    let factor = if matches!(
                        operation,
                        BgvCircuitOperation::Add { .. } | BgvCircuitOperation::Subtract { .. }
                    ) {
                        let alignment = align(left.correction_factor, right.correction_factor, p);
                        add(
                            "left integer phase after factor alignment",
                            &left.phase_bound * centered_abs(alignment.lhs_scale, p),
                        );
                        add(
                            "right integer phase after factor alignment",
                            &right.phase_bound * centered_abs(alignment.rhs_scale, p),
                        );
                        alignment.factor
                    } else {
                        let factor = multiply(left.correction_factor, right.correction_factor, p);
                        add(
                            "tensor integer phase including plaintext carry",
                            UBig::from(n) * &left.phase_bound * &right.phase_bound,
                        );
                        for term in plan.key_terms(level, &backend, &e, &h, true)? {
                            add(term.label, term.bound);
                        }
                        factor
                    };
                    (level, factor)
                }
                BgvCircuitOperation::AddPlain { input, plaintext }
                | BgvCircuitOperation::MultiplyPlain { input, plaintext } => {
                    let input = plan.operand(node, *input)?;
                    if plaintext.n != n || plaintext.p != p {
                        return Err(BgvPlanningError::Circuit {
                            node,
                            reason: "public plaintext bounds belong to another N or p",
                        });
                    }
                    if matches!(operation, BgvCircuitOperation::AddPlain { .. }) {
                        add("input integer phase", input.phase_bound.clone());
                        let bound = if input.correction_factor == 1 {
                            plaintext.infinity
                        } else {
                            // Norms alone do not determine the norm after a
                            // factor multiplication modulo p. Use the complete
                            // selected embedding range rather than guessing it.
                            message_bound(p, plaintext.embedding)
                        };
                        add("factor-encoded public plaintext lift", UBig::from(bound));
                    } else {
                        add(
                            "input phase times public plaintext l1 norm",
                            &input.phase_bound * &plaintext.one,
                        );
                    }
                    (input.level, input.correction_factor)
                }
                BgvCircuitOperation::Automorphism { input, exponent } => {
                    if (*exponent).is_multiple_of(2) || *exponent >= n.saturating_mul(2) {
                        return Err(BgvPlanningError::Circuit {
                            node,
                            reason: "automorphism exponent must be odd and below 2N",
                        });
                    }
                    let input = plan.operand(node, *input)?;
                    let level = input.level;
                    let factor = input.correction_factor;
                    add("signed coefficient permutation", input.phase_bound.clone());
                    for term in plan.key_terms(level, &backend, &e, &h, false)? {
                        add(term.label, term.bound);
                    }
                    (level, factor)
                }
                BgvCircuitOperation::KeySwitch { input } => {
                    let input = plan.operand(node, *input)?;
                    let level = input.level;
                    let factor = input.correction_factor;
                    add("input integer phase", input.phase_bound.clone());
                    for term in plan.key_terms(level, &backend, &e, &h, false)? {
                        add(term.label, term.bound);
                    }
                    (level, factor)
                }
                BgvCircuitOperation::DropPrime { input } => {
                    let input = plan.operand(node, *input)?;
                    if input.level + 1 >= context.level_count() {
                        return Err(BgvPlanningError::Circuit {
                            node,
                            reason: "prime drop requires another prepared nonempty prefix level",
                        });
                    }
                    let q = *context
                        .base_q(input.level)
                        .moduli_values()
                        .last()
                        .expect("nonempty context basis");
                    add(
                        "divided input integer phase",
                        ceil(input.phase_bound.clone(), UBig::from(q)),
                    );
                    add(
                        "p-preserving component corrections",
                        ceil(UBig::from(p) * (q - 1) * (&h + 1u8), UBig::from(q) * 2u8),
                    );
                    (
                        input.level + 1,
                        multiply(input.correction_factor, inverse(q % p, p), p),
                    )
                }
            };
            let phase_bound = terms.iter().fold(UBig::ZERO, |sum, term| sum + &term.bound);
            let capacity = product(context.base_q(level).moduli_values()) / 2u8;
            if phase_bound > capacity {
                return Err(BgvPlanningError::Recovery {
                    node,
                    level,
                    phase_bound: phase_bound.to_string(),
                    capacity: capacity.to_string(),
                    required_modulus_bits: (&phase_bound * 2u8 + 1u8).bit_len(),
                });
            }
            let margin = &capacity - &phase_bound;
            let error_bound = (&phase_bound + p / 2) / p;
            plan.steps.push(BgvBudgetStep {
                node,
                level,
                correction_factor,
                terms,
                phase_bound,
                error_bound,
                capacity,
                margin,
            });
        }
        Ok(plan)
    }

    /// Ordered public error/phase ledger, including capacity and remaining margin.
    #[must_use]
    pub fn steps(&self) -> &[BgvBudgetStep] {
        &self.steps
    }

    /// Actual prepared backend for ordinary role-key generation at a used level.
    ///
    /// Returns `None` for an unprepared or key-free level. Matching configuration
    /// does not prove a key was generated as an ordinary single-owner key under
    /// the intended actual secret; that relationship remains a caller contract.
    #[must_use]
    pub fn key_config(&self, level: usize) -> Option<BgvEvaluationKeyConfig> {
        self.keys.get(level).and_then(Clone::clone)
    }

    /// Exact public inputs for separate RLWE attack estimation, with no claimed security level.
    ///
    /// The first entry is the data-Q encryption/public-key domain. Remaining
    /// entries include every actually used Hybrid key-level QP domain. Ordinary
    /// evaluation keys additionally require their correlated/circular-security
    /// assumptions; a numerical attack estimate is not that proof.
    #[must_use]
    pub fn security_inputs(&self) -> &[RlweSecurityInput] {
        &self.security_inputs
    }

    fn operand(&self, node: usize, index: usize) -> Result<&BgvBudgetStep, BgvPlanningError> {
        self.steps.get(index).ok_or(BgvPlanningError::Circuit {
            node,
            reason: "operand must reference an earlier operation",
        })
    }

    fn key_terms(
        &mut self,
        level: usize,
        backend: &BgvBudgetBackend,
        e: &UBig,
        h: &UBig,
        quadratic: bool,
    ) -> Result<Vec<BgvBudgetTerm>, BgvPlanningError> {
        let parameters = self.context.parameters();
        let n = parameters.poly_length().get();
        let p = parameters.plain_modulus().value();
        if self.keys[level].is_none() {
            self.keys[level] = Some(match backend {
                BgvBudgetBackend::Radix(config) => {
                    self.context.radix_key_parameters(level, *config)?.into()
                }
                BgvBudgetBackend::Hybrid {
                    decomposition_count,
                    auxiliary_moduli,
                } => {
                    let prepared = self.context.hybrid_key_parameters(
                        level,
                        *decomposition_count,
                        auxiliary_moduli,
                    )?;
                    let sampling = parameters.encryption_parameters();
                    let input = security_input(
                        sampling,
                        self.context.base_q(level).moduli_values(),
                        auxiliary_moduli,
                    )?;
                    self.security_inputs.push(input);
                    prepared.into()
                }
            });
        }
        match self.keys[level]
            .as_ref()
            .expect("prepared key configuration")
        {
            BgvEvaluationKeyConfig::PreparedRadix(parameters) => {
                let basis = parameters.basis();
                let residual = if basis.drop_bits() == 0 {
                    UBig::ZERO
                } else {
                    UBig::ONE << (basis.drop_bits() - 1) as usize
                };
                let source_norm = if quadratic { h * h } else { h.clone() };
                Ok(vec![
                    BgvBudgetTerm {
                        label: "p-scaled radix digit/key error",
                        bound: UBig::from(p)
                            * n
                            * basis.level_count().get()
                            * (basis.basis_value() / 2)
                            * e,
                    },
                    BgvBudgetTerm {
                        label: "p-scaled truncated radix residual times role secret",
                        bound: UBig::from(p) * residual * source_norm,
                    },
                ])
            }
            BgvEvaluationKeyConfig::Hybrid(parameters) => {
                let hybrid = parameters.hybrid_rns();
                let mut key_error = UBig::ZERO;
                for partition in hybrid.partitions() {
                    let range = partition.q_range();
                    let qj = product(&hybrid.q_base().moduli_values()[range]);
                    key_error += UBig::from(n) * (range.end - range.start) * qj * e;
                }
                let p_key = product(hybrid.p_base().moduli_values());
                Ok(vec![
                    BgvBudgetTerm {
                        label: "p-scaled actual Hybrid digit/key error divided by P",
                        bound: ceil(UBig::from(p) * key_error, p_key.clone()),
                    },
                    BgvBudgetTerm {
                        label: "p-scaled centered Hybrid component ModDown",
                        bound: ceil(UBig::from(p) * (&p_key - 1u8) * (h + 1u8), p_key * 2u8),
                    },
                ])
            }
            BgvEvaluationKeyConfig::Radix(_) => {
                unreachable!("planner retains prepared radix parameters")
            }
        }
    }
}

fn message_bound(p: u64, embedding: PlaintextEmbedding) -> u64 {
    match embedding {
        PlaintextEmbedding::Unsigned => p - 1,
        PlaintextEmbedding::Centered => p / 2,
    }
}
fn product(values: &[u64]) -> UBig {
    values.iter().fold(UBig::ONE, |p, &q| p * q)
}
fn ceil(numerator: UBig, denominator: UBig) -> UBig {
    (&numerator + &denominator - 1u8) / denominator
}
