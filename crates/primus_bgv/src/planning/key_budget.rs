//! Admission and resource preparation for BGV's actual per-level key backend.
use std::sync::Arc;

use dashu_int::UBig;
use primus_decompose::DecompositionConfig;
use primus_glwe_rns::rlwe_parameters::{search_ntt_primes, security_input};
use primus_lattice::hybrid::{NativeHybridAuxiliary, NativeHybridParameters};

use crate::BgvContext;
use crate::correction::gcd;
use crate::keys::{BgvEvaluationKeyConfig, BgvEvaluationKeyError};

use super::{BgvBudgetTerm, BgvCircuitPlan, BgvPlanningError, ceil, from_words};

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

// Cached only during admission. The finished plan keeps the prepared keys and
// per-node ledger, so a rejected circuit does not leave separate resource state.
pub(super) struct KeyBudgets<'a> {
    backend: BgvBudgetBackend,
    levels: Vec<Option<LevelKeyBudget>>,
    auxiliary: Option<Arc<NativeHybridAuxiliary>>,
    error_support: &'a UBig,
    secret_norm: &'a UBig,
}

impl<'a> KeyBudgets<'a> {
    pub(super) fn new(
        backend: BgvBudgetBackend,
        level_count: usize,
        error_support: &'a UBig,
        secret_norm: &'a UBig,
    ) -> Self {
        Self {
            backend,
            levels: std::iter::repeat_with(|| None).take(level_count).collect(),
            auxiliary: None,
            error_support,
            secret_norm,
        }
    }

    pub(super) fn terms(
        &mut self,
        plan: &mut BgvCircuitPlan<'_>,
        level: usize,
        quadratic: bool,
    ) -> Result<[BgvBudgetTerm; 2], BgvPlanningError> {
        if self.levels[level].is_none() {
            let context = plan.context;
            let parameters = context.parameters();
            let config = match &self.backend {
                BgvBudgetBackend::Radix(config) => {
                    context.radix_key_parameters(level, *config)?.into()
                }
                BgvBudgetBackend::Hybrid {
                    decomposition_count,
                    auxiliary_moduli,
                } => {
                    if self.auxiliary.is_none() {
                        self.auxiliary = Some(Arc::new(
                            NativeHybridAuxiliary::try_new(
                                parameters.poly_length(),
                                auxiliary_moduli,
                            )
                            .map_err(BgvEvaluationKeyError::from)?,
                        ));
                    }
                    let prepared = NativeHybridParameters::try_with_auxiliary(
                        context.base_q(level),
                        parameters.base_q().moduli_count(),
                        Arc::clone(self.auxiliary.as_ref().expect("prepared key P")),
                        *decomposition_count,
                    )
                    .map_err(BgvEvaluationKeyError::from)?;
                    let input = security_input(
                        parameters.encryption_parameters(),
                        context.base_q(level).moduli_values(),
                        auxiliary_moduli,
                    )?;
                    plan.security_inputs.push(input);
                    BgvEvaluationKeyConfig::Hybrid(Arc::new(prepared))
                }
            };
            self.levels[level] = Some(LevelKeyBudget::new(
                &config,
                parameters.poly_length().get(),
                parameters.plain_modulus().value(),
                self.error_support,
                self.secret_norm,
            ));
            plan.keys[level] = Some(config);
        }
        Ok(self.levels[level]
            .as_ref()
            .expect("prepared level budget")
            .terms(quadratic))
    }
}

struct LevelKeyBudget {
    sampling: BgvBudgetTerm,
    correction: BgvBudgetTerm,
    quadratic_correction: Option<UBig>,
}

impl LevelKeyBudget {
    fn new(
        config: &BgvEvaluationKeyConfig,
        n: usize,
        p: u64,
        error_support: &UBig,
        secret_norm: &UBig,
    ) -> Self {
        match config {
            BgvEvaluationKeyConfig::PreparedRadix(parameters) => {
                let basis = parameters.basis();
                let residual = if basis.drop_bits() == 0 {
                    UBig::ZERO
                } else {
                    UBig::ONE << (basis.drop_bits() - 1) as usize
                };
                let linear_correction = UBig::from(p) * residual * secret_norm;
                Self {
                    sampling: BgvBudgetTerm {
                        label: "p-scaled radix digit/key error",
                        bound: UBig::from(p)
                            * n
                            * basis.level_count().get()
                            * (basis.basis_value() / 2)
                            * error_support,
                    },
                    quadratic_correction: Some(&linear_correction * secret_norm),
                    correction: BgvBudgetTerm {
                        label: "p-scaled truncated radix residual times role secret",
                        bound: linear_correction,
                    },
                }
            }
            BgvEvaluationKeyConfig::Hybrid(parameters) => {
                let hybrid = parameters.hybrid_rns();
                let mut key_error = UBig::ZERO;
                for partition in hybrid.partitions() {
                    let qj: UBig = hybrid.q_base().moduli_values()[partition.q_range()]
                        .iter()
                        .copied()
                        .map(UBig::from)
                        .product();
                    key_error += UBig::from(n) * partition.moduli_count() * qj * error_support;
                }
                let p_key = from_words(hybrid.p_base().moduli_product().0);
                Self {
                    sampling: BgvBudgetTerm {
                        label: "p-scaled actual Hybrid digit/key error divided by P",
                        bound: ceil(UBig::from(p) * key_error, p_key.clone()),
                    },
                    correction: BgvBudgetTerm {
                        label: "p-scaled centered Hybrid component ModDown",
                        bound: ceil(
                            UBig::from(p) * (&p_key - 1u8) * (secret_norm + 1u8),
                            p_key * 2u8,
                        ),
                    },
                    quadratic_correction: None,
                }
            }
            BgvEvaluationKeyConfig::Radix(_) => {
                unreachable!("planner retains prepared radix parameters")
            }
        }
    }

    fn terms(&self, quadratic: bool) -> [BgvBudgetTerm; 2] {
        let correction = if quadratic {
            self.quadratic_correction
                .as_ref()
                .unwrap_or(&self.correction.bound)
        } else {
            &self.correction.bound
        };
        [
            self.sampling.clone(),
            BgvBudgetTerm {
                label: self.correction.label,
                bound: correction.clone(),
            },
        ]
    }
}
