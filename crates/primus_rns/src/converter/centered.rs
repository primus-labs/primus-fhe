use crate::{BaseConverter, RNSBase, Residues, RnsError};
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_reduce::{Reduce, ReduceMul, ReduceSub};
type Base = RNSBase<u64, BarrettModulus<u64>>;

/// Reusable allocation-free storage for exact centered basis conversion.
///
/// Construct through [`CenteredBaseConverter::workspace`]; it stores adjusted
/// CRT residues and exact half-boundary fallback buffers, without HPS scaling
/// resources.
pub struct CenteredConversionWorkspace {
    pub(crate) adjusted: Vec<u64>,
    pub(crate) corrections: Vec<u64>,
    pub(crate) residues: Vec<u64>,
    pub(crate) value: Vec<u64>,
}

/// Exact centered conversion between odd u64 bases below 2^62.
///
/// Fast CRT corrections are accepted only when a conservative floating point
/// interval excludes the half boundary. Uncertain cases use exact multiword
/// composition. Bases share their immutable CRT precomputation.
pub struct CenteredBaseConverter {
    converter: BaseConverter<u64, BarrettModulus<u64>>,
    product_mod_output: Vec<u64>,
    half_product: Vec<u64>,
    inverse_moduli: Vec<f64>,
    quotient_error: f64,
}

impl CenteredBaseConverter {
    pub(crate) fn input_base(&self) -> &Base {
        &self.converter.input_base
    }
    pub(crate) fn output_base(&self) -> &Base {
        &self.converter.output_base
    }
    /// Prepares exact centered conversion for ordered canonical residues.
    ///
    /// # Errors
    /// Rejects even moduli or moduli outside [3,2^62).
    pub fn try_new(input: &Base, output: &Base) -> Result<Self, RnsError> {
        Self::validate_bases(input, output)?;
        Ok(Self::new(input, output))
    }

    /// Adds exact centered correction to an already prepared base converter.
    ///
    /// The converter's bases and conversion matrix are retained, so an existing
    /// approximate converter can share the same resources with this exact lift.
    /// Only the centered product, half-boundary and quotient-error constants are
    /// prepared here.
    ///
    /// # Errors
    /// Rejects even moduli or moduli outside [3,2^62), as [`Self::try_new`].
    pub fn try_from_converter(
        converter: BaseConverter<u64, BarrettModulus<u64>>,
    ) -> Result<Self, RnsError> {
        Self::validate_bases(&converter.input_base, &converter.output_base)?;
        Ok(Self::from_converter(converter))
    }

    fn validate_bases(input: &Base, output: &Base) -> Result<(), RnsError> {
        for &modulus in input.moduli_values().iter().chain(output.moduli_values()) {
            if !(3..(1 << 62)).contains(&modulus) || modulus & 1 == 0 {
                return Err(RnsError::UnsupportedHpsModulus { modulus });
            }
        }
        Ok(())
    }

    /// Prepares reusable scratch for one exact batch length.
    ///
    /// # Panics
    /// Panics when complete storage geometry overflows.
    #[must_use]
    pub fn workspace(&self, value_count: usize) -> CenteredConversionWorkspace {
        let input = &self.converter.input_base;
        CenteredConversionWorkspace {
            adjusted: vec![
                0;
                input
                    .moduli_count()
                    .checked_mul(value_count)
                    .expect("centered conversion workspace length overflow")
            ],
            corrections: vec![0; value_count],
            residues: vec![0; input.moduli_count()],
            value: vec![0; input.big_uint_value_len()],
        }
    }

    /// Writes exact centered source representatives reduced in the target base.
    ///
    /// Arrays are modulus-major and residues must be canonical. Complete input,
    /// output and workspace lengths are validated before writes. All online
    /// conversion, including exact boundary fallback, reuses supplied storage.
    ///
    /// # Panics
    /// Panics on mismatched complete shapes or overflowing lengths.
    pub fn convert_to(
        &self,
        input: &[u64],
        output: &mut [u64],
        value_count: usize,
        workspace: &mut CenteredConversionWorkspace,
    ) {
        let source = &self.converter.input_base;
        let destination = &self.converter.output_base;
        assert_eq!(
            input.len(),
            source
                .moduli_count()
                .checked_mul(value_count)
                .expect("centered conversion input length overflow")
        );
        assert_eq!(
            output.len(),
            destination
                .moduli_count()
                .checked_mul(value_count)
                .expect("centered conversion output length overflow")
        );
        assert_eq!(workspace.corrections.len(), value_count);
        assert!(workspace.adjusted.len() >= input.len());
        assert!(workspace.residues.len() >= source.moduli_count());
        assert!(workspace.value.len() >= source.big_uint_value_len());
        self.expand(input, output, value_count, workspace);
    }
    pub(crate) fn new(input: &Base, output: &Base) -> Self {
        Self::from_converter(BaseConverter::new(input, output))
    }

    fn from_converter(converter: BaseConverter<u64, BarrettModulus<u64>>) -> Self {
        let input = &converter.input_base;
        let output = &converter.output_base;
        let product = input.moduli_product();
        let words = product.digits();
        let half_product = words
            .iter()
            .enumerate()
            .map(|(i, &word)| (word >> 1) | (words.get(i + 1).copied().unwrap_or(0) << 63))
            .collect();
        let count = input.moduli_count() as f64;
        let product_mod_output = output.moduli().iter().map(|p| p.reduce(words)).collect();
        let inverse_moduli = input
            .moduli_values()
            .iter()
            .map(|&q| 1.0 / q as f64)
            .collect();
        Self {
            converter,
            product_mod_output,
            half_product,
            inverse_moduli,
            // With u=2^-53 the cast/reciprocal/multiply chain contributes <5u
            // absolute error per term in [0,1]. Sequential addition contributes
            // <2u*k^2 for k*u<1/4. This deliberately larger bound also covers
            // the rounding in sum+0.5 and the boundary-distance comparison.
            // For larger k it exceeds 1/2, so every value takes exact fallback.
            quotient_error: (count + 2.0) * (count + 2.0) * 2.0_f64.powi(-48),
        }
    }

    pub(crate) fn expand(
        &self,
        input: &[u64],
        output: &mut [u64],
        n: usize,
        workspace: &mut CenteredConversionWorkspace,
    ) {
        if n == 0 {
            return;
        }
        let source = &self.converter.input_base;
        let destination = &self.converter.output_base;
        let count = source.moduli_count();
        if count == 1 {
            let q = source.moduli_values()[0];
            let half = q / 2;
            for ((chunk, modulus), &q_mod_p) in output
                .chunks_exact_mut(n)
                .zip(destination.moduli())
                .zip(&self.product_mod_output)
            {
                let p = modulus.value();
                // Every centered magnitude is at most floor(q/2).
                if half < p {
                    for (out, &value) in chunk.iter_mut().zip(input) {
                        *out = if value > half { p - (q - value) } else { value };
                    }
                } else {
                    for (out, &value) in chunk.iter_mut().zip(input) {
                        let value_p = modulus.reduce(value);
                        *out = if value > half {
                            modulus.reduce_sub(value_p, q_mod_p)
                        } else {
                            value_p
                        };
                    }
                }
            }
            return;
        }
        let adjusted = &mut workspace.adjusted[..input.len()];
        self.converter
            .fast_convert_array(input, output, n, adjusted);
        for (correction, residues) in workspace
            .corrections
            .iter_mut()
            .zip(adjusted.chunks_exact(count))
        {
            let sum = residues
                .iter()
                .zip(&self.inverse_moduli)
                .map(|(&x, &inverse)| x as f64 * inverse)
                .sum::<f64>();
            let nearest = (sum + 0.5).floor();
            *correction = if (sum - nearest).abs() + self.quotient_error < 0.5 {
                nearest as u64
            } else {
                u64::MAX
            };
        }
        for ((chunk, p), &product) in output
            .chunks_exact_mut(n)
            .zip(destination.moduli())
            .zip(&self.product_mod_output)
        {
            for (out, &correction) in chunk.iter_mut().zip(&workspace.corrections) {
                if correction != u64::MAX {
                    *out = p.reduce_sub(*out, p.reduce_mul(p.reduce(correction), product));
                }
            }
        }
        for (index, &correction) in workspace.corrections.iter().enumerate() {
            if correction != u64::MAX {
                continue;
            }
            let residues = &mut workspace.residues[..count];
            for (residue, chunk) in residues.iter_mut().zip(input.chunks_exact(n)) {
                *residue = chunk[index];
            }
            let value = &mut workspace.value[..source.big_uint_value_len()];
            source.compose_to(Residues(residues), BigUint(value));
            let negative = value
                .iter()
                .rev()
                .cmp(self.half_product.iter().rev())
                .is_gt();
            for ((chunk, p), &product) in output
                .chunks_exact_mut(n)
                .zip(destination.moduli())
                .zip(&self.product_mod_output)
            {
                let reduced = p.reduce(&*value);
                chunk[index] = if negative {
                    p.reduce_sub(reduced, product)
                } else {
                    reduced
                };
            }
        }
    }
}
