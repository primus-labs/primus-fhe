//! Exact temporary prefix reduction and scaled restoration, with one table owner.
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_reduce::{Reduce, ReduceMul};

use crate::{BfvContext, evaluation::BfvModulusSwitch, keys::BfvEvaluationKeyError};

/// Internal arithmetic resources, independent of multiplication/key-switch policy.
/// Restoring maps y modulo Q_l to D*y modulo Q, D=Q/Q_l. It is not ordinary
/// centered basis extension, and never creates a second context or NTT table.
pub(crate) struct WorkingBasis<'a> {
    external_level: usize,
    working_level: usize,
    n: usize,
    external_len: usize,
    working_len: usize,
    reductions: Vec<BfvModulusSwitch<'a>>,
    buffers: [Vec<u64>; 2],
    restore: Vec<ShoupFactor<u64>>,
    moduli: &'a [primus_modulus::BarrettModulus<u64>],
}

impl<'a> WorkingBasis<'a> {
    pub(crate) fn try_new(
        context: &'a BfvContext,
        external_level: usize,
        working_level: usize,
    ) -> Result<Self, BfvEvaluationKeyError> {
        for level in [external_level, working_level] {
            if level >= context.level_count() {
                return Err(BfvEvaluationKeyError::Level {
                    requested: level,
                    available: context.level_count(),
                });
            }
        }
        if working_level < external_level {
            return Err(BfvEvaluationKeyError::WorkingLevel {
                external: external_level,
                working: working_level,
            });
        }
        let n = context.parameters().poly_length().get();
        let external_len = context.rns_poly_len(external_level);
        let working_len = context.rns_poly_len(working_level);
        let gap = working_level - external_level;
        let external_moduli = context.codec(external_level).base_q().moduli();
        let moduli = context.codec(working_level).base_q().moduli();
        let restore = if gap == 0 {
            Vec::new()
        } else {
            moduli
                .iter()
                .map(|&q| {
                    let d = external_moduli[moduli.len()..]
                        .iter()
                        .fold(1, |d, prime| q.reduce_mul(d, q.reduce(prime.value())));
                    ShoupFactor::new(d, q.value())
                })
                .collect()
        };
        Ok(Self {
            external_level,
            working_level,
            n,
            external_len,
            working_len,
            reductions: (external_level..working_level)
                .map(|level| BfvModulusSwitch::new(context, level))
                .collect(),
            buffers: [
                if gap >= 2 {
                    vec![0; external_len - n]
                } else {
                    Vec::new()
                },
                if gap >= 3 {
                    vec![0; external_len - 2 * n]
                } else {
                    Vec::new()
                },
            ],
            restore,
            moduli,
        })
    }

    pub(crate) fn external_level(&self) -> usize {
        self.external_level
    }
    pub(crate) fn working_level(&self) -> usize {
        self.working_level
    }
    pub(crate) fn external_poly_len(&self) -> usize {
        self.external_len
    }
    pub(crate) fn working_poly_len(&self) -> usize {
        self.working_len
    }

    // The caller validates both complete [c0,c1] lengths, or owns the
    // destination scratch at the working level.
    pub(crate) fn shrink_ciphertext_to(&mut self, input: &[u64], output: &mut [u64]) {
        for (input, output) in input
            .chunks_exact(self.external_len)
            .zip(output.chunks_exact_mut(self.working_len))
        {
            self.shrink_polynomial_to(input, output);
        }
    }

    // Odd nearest divisions compose exactly. For odd a,b and integer x,
    // floor((floor((x+(a-1)/2)/a)+(b-1)/2)/b)
    // = floor((x+(a*b-1)/2)/(a*b)). Canonical wraps differ by Q_l multiples,
    // so this also proves exact simultaneous rounding in the retained ring.
    // Input and output are complete polynomials in their respective bases.
    pub(crate) fn shrink_polynomial_to(&mut self, input: &[u64], output: &mut [u64]) {
        let count = self.reductions.len();
        if count == 0 {
            output.copy_from_slice(input);
            return;
        }
        if count == 1 {
            self.reductions[0].switch_component(input, output);
            return;
        }
        let (first, second) = self.buffers.split_at_mut(1);
        self.reductions[0].switch_component(input, &mut first[0]);
        for index in 1..count {
            let source_len = self.external_len - index * self.n;
            let destination_len = source_len - self.n;
            if index + 1 == count {
                let source = if index % 2 == 1 {
                    &first[0]
                } else {
                    &second[0]
                };
                self.reductions[index].switch_component(&source[..source_len], output);
            } else if index % 2 == 1 {
                self.reductions[index]
                    .switch_component(&first[0][..source_len], &mut second[0][..destination_len]);
            } else {
                self.reductions[index]
                    .switch_component(&second[0][..source_len], &mut first[0][..destination_len]);
            }
        }
    }

    // The caller supplies a complete working ciphertext and a validated
    // external [c0,c1] destination.
    pub(crate) fn restore_ciphertext_to(&self, input: &[u64], output: &mut [u64]) {
        if self.reductions.is_empty() {
            output.copy_from_slice(input);
            return;
        }
        for (input, output) in input
            .chunks_exact(self.working_len)
            .zip(output.chunks_exact_mut(self.external_len))
        {
            let (retained, omitted) = output.split_at_mut(self.working_len);
            retained.copy_from_slice(input);
            omitted.fill(0);
            for ((limb, &factor), modulus) in retained
                .chunks_exact_mut(self.n)
                .zip(&self.restore)
                .zip(self.moduli)
            {
                factor.factor_mul_slice_assign(limb, modulus.value());
            }
        }
    }
}
