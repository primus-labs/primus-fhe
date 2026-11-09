//! Shared Boolean gate preprocessing, LUTs and reusable evaluation workspace.

use crate::{LookupTable, Lwe, LweCiphertext, ProgrammableBootstrap, TfheEvaluationError};
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_reduce::RingContext;
use primus_shape::PolyLength;

/// The number of bits in the external Boolean plaintext modulus: `t = 2^2 = 4`.
pub const BOOLEAN_PLAINTEXT_BITS: u32 = 2;

/// A binary Boolean gate evaluated by one programmable bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BooleanGate {
    /// Logical conjunction.
    And,
    /// Negated logical conjunction.
    Nand,
    /// Logical disjunction.
    Or,
    /// Negated logical disjunction.
    Nor,
    /// Logical exclusive disjunction.
    Xor,
    /// Logical equivalence.
    Xnor,
}

impl BooleanGate {
    #[inline]
    fn lookup_table_index(self) -> usize {
        match self {
            Self::And => 0,
            Self::Nand => 1,
            Self::Or | Self::Xor => 2,
            Self::Nor | Self::Xnor => 3,
        }
    }
}

/// Backend-independent Boolean gate evaluator.
///
/// The backend supplies only programmable bootstrapping; Boolean encodings,
/// affine gate preprocessing, and accumulators are shared.
/// Gate LUTs use opposite values at the rounded modulus-8 scale. After PBS,
/// a positive shift at that scale restores the external 0/1 encoding modulo 4.
/// These signed LUT values are internal accumulator values, not external
/// Boolean plaintext representatives.
///
/// # Correctness
///
/// Inputs must encode 0/1 with unsigned rounded encoding modulo 4, under the
/// configured external key and ciphertext modulus. Explicit-modulus coefficients
/// must be canonical. Encoding and key identity cannot be checked from raw LWE
/// ciphertexts; the PBS backend's noise requirements also apply.
///
/// # Panics
///
/// Online operations panic when passed ciphertexts with a dimension different
/// from the configured external LWE dimension.
pub struct BooleanEvaluator<T, M, E>
where
    T: FheUint,
    M: RingContext<T>,
    E: ProgrammableBootstrap<T>,
{
    ciphertext_modulus: M,
    external_lwe_dimension: LweDimension,
    encoded_one: T,
    bootstrapper: E,
    gate_lookup_tables: [LookupTable<T>; 4],
    output_shift: T,
    gate_input: LweCiphertext<T>,
    mux_branch: LweCiphertext<T>,
}

impl<T, M, E> BooleanEvaluator<T, M, E>
where
    T: FheUint,
    M: RingContext<T>,
    E: ProgrammableBootstrap<T>,
{
    /// Creates gate LUTs and reusable workspace for a complete PBS backend.
    /// Requires rounded input modulus 4 and ciphertext moduli large enough for
    /// the internal modulus-8 encoding. Backend context factories bind these
    /// arguments automatically and return the same evaluation error type.
    ///
    /// # Correctness
    ///
    /// The dimension, input codec, accumulator length and coefficient modulus
    /// must describe `bootstrapper`. It must preserve the LUT output scale as
    /// required by [`ProgrammableBootstrap::apply_lookup_table_to`]. The trait
    /// cannot verify this binding or secret-key identity.
    pub fn try_new<GM>(
        external_lwe_dimension: LweDimension,
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, M>,
        coefficient_modulus: GM,
        bootstrapper: E,
    ) -> Result<Self, TfheEvaluationError>
    where
        GM: RingContext<T>,
    {
        let ciphertext_modulus = input_codec.ciphertext_modulus();
        let internal_plaintext_modulus = T::ONE << (BOOLEAN_PLAINTEXT_BITS + 1);
        let moduli = [
            ciphertext_modulus.explicit_value(),
            coefficient_modulus.explicit_value(),
        ];
        if input_codec.plaintext_modulus() != T::ONE << BOOLEAN_PLAINTEXT_BITS
            || moduli
                .into_iter()
                .flatten()
                .any(|q| q <= internal_plaintext_modulus)
        {
            return Err(TfheEvaluationError::InvalidBooleanEncoding);
        }
        let encoded_one = input_codec.encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        let positive_value = RoundedCodec::new(internal_plaintext_modulus, coefficient_modulus)
            .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        let negative_value = coefficient_modulus.reduce_neg(positive_value);
        let compile = |positive: [bool; 2]| {
            LookupTable::try_new(
                2,
                poly_length,
                input_codec.plaintext_modulus(),
                ciphertext_modulus,
                coefficient_modulus,
                |input| {
                    Ok(if positive[input] {
                        positive_value
                    } else {
                        negative_value
                    })
                },
            )
        };
        let gate_lookup_tables = [
            compile([false, false])?,
            compile([true, true])?,
            compile([false, true])?,
            compile([true, false])?,
        ];
        let output_shift = RoundedCodec::new(internal_plaintext_modulus, ciphertext_modulus)
            .encode_value(T::ONE, PlaintextEmbedding::Unsigned);
        Ok(Self {
            ciphertext_modulus,
            external_lwe_dimension,
            encoded_one,
            bootstrapper,
            gate_lookup_tables,
            output_shift,
            gate_input: LweCiphertext::zero(external_lwe_dimension.get()),
            mux_branch: LweCiphertext::zero(external_lwe_dimension.get()),
        })
    }

    /// Evaluates a binary gate and allocates its output ciphertext.
    #[must_use]
    pub fn evaluate_binary(
        &mut self,
        gate: BooleanGate,
        lhs: Lwe<&[T]>,
        rhs: Lwe<&[T]>,
    ) -> LweCiphertext<T> {
        let mut output = LweCiphertext::zero(self.external_lwe_dimension.get());
        self.evaluate_binary_to(gate, lhs, rhs, output.as_mut_view());
        output
    }

    /// Evaluates a binary gate into an existing output allocation.
    pub fn evaluate_binary_to(
        &mut self,
        gate: BooleanGate,
        lhs: Lwe<&[T]>,
        rhs: Lwe<&[T]>,
        mut output: Lwe<&mut [T]>,
    ) {
        prepare_binary_gate(
            gate,
            lhs,
            rhs,
            self.gate_input.as_mut_view(),
            self.ciphertext_modulus,
        );
        let lookup_table = &self.gate_lookup_tables[gate.lookup_table_index()];
        self.bootstrapper.apply_lookup_table_to(
            self.gate_input.as_view(),
            lookup_table,
            output.as_mut_view(),
        );
        self.ciphertext_modulus
            .reduce_add_assign(output.b_mut(), self.output_shift);
    }

    /// Evaluates an AND gate.
    #[must_use]
    #[inline]
    pub fn and(&mut self, lhs: Lwe<&[T]>, rhs: Lwe<&[T]>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::And, lhs, rhs)
    }

    /// Evaluates a NAND gate.
    #[must_use]
    #[inline]
    pub fn nand(&mut self, lhs: Lwe<&[T]>, rhs: Lwe<&[T]>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Nand, lhs, rhs)
    }

    /// Evaluates an OR gate.
    #[must_use]
    #[inline]
    pub fn or(&mut self, lhs: Lwe<&[T]>, rhs: Lwe<&[T]>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Or, lhs, rhs)
    }

    /// Evaluates a NOR gate.
    #[must_use]
    #[inline]
    pub fn nor(&mut self, lhs: Lwe<&[T]>, rhs: Lwe<&[T]>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Nor, lhs, rhs)
    }

    /// Evaluates an XOR gate.
    #[must_use]
    #[inline]
    pub fn xor(&mut self, lhs: Lwe<&[T]>, rhs: Lwe<&[T]>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Xor, lhs, rhs)
    }

    /// Evaluates an XNOR gate.
    #[must_use]
    #[inline]
    pub fn xnor(&mut self, lhs: Lwe<&[T]>, rhs: Lwe<&[T]>) -> LweCiphertext<T> {
        self.evaluate_binary(BooleanGate::Xnor, lhs, rhs)
    }

    /// Selects 'then_value' when 'condition' is true and 'else_value'
    /// otherwise.
    ///
    /// This uses two bootstrapped AND terms followed by one LWE addition.
    #[must_use]
    pub fn mux(
        &mut self,
        condition: Lwe<&[T]>,
        then_value: Lwe<&[T]>,
        else_value: Lwe<&[T]>,
    ) -> LweCiphertext<T> {
        let mut output = LweCiphertext::zero(self.external_lwe_dimension.get());
        self.mux_to(condition, then_value, else_value, output.as_mut_view());
        output
    }

    /// Evaluates a multiplexer into an existing output allocation.
    pub fn mux_to(
        &mut self,
        condition: Lwe<&[T]>,
        then_value: Lwe<&[T]>,
        else_value: Lwe<&[T]>,
        mut output: Lwe<&mut [T]>,
    ) {
        prepare_binary_gate(
            BooleanGate::And,
            condition.as_view(),
            then_value,
            self.gate_input.as_mut_view(),
            self.ciphertext_modulus,
        );
        self.bootstrapper.apply_lookup_table_to(
            self.gate_input.as_view(),
            &self.gate_lookup_tables[BooleanGate::And.lookup_table_index()],
            self.mux_branch.as_mut_view(),
        );
        let modulus = self.ciphertext_modulus;
        modulus.reduce_add_assign(self.mux_branch.b_mut(), self.output_shift);

        assert_dimension(else_value.as_view(), self.external_lwe_dimension.get());
        self.gate_input.0.copy_from_slice(else_value.as_ref());
        self.gate_input.sub_assign(&condition, modulus);
        modulus.reduce_add_assign(self.gate_input.b_mut(), self.encoded_one);

        self.bootstrapper.apply_lookup_table_to(
            self.gate_input.as_view(),
            &self.gate_lookup_tables[BooleanGate::And.lookup_table_index()],
            output.as_mut_view(),
        );
        modulus.reduce_add_assign(output.b_mut(), self.output_shift);
        output.add_assign(&self.mux_branch, modulus);
    }

    /// Negates a Boolean ciphertext without programmable bootstrapping.
    #[must_use]
    pub fn not(&self, input: Lwe<&[T]>) -> LweCiphertext<T> {
        assert_dimension(input.as_view(), self.external_lwe_dimension.get());
        let mut output = LweCiphertext::new(input.as_ref().to_vec());
        self.not_assign(output.as_mut_view());
        output
    }

    /// Negates a Boolean ciphertext into an existing allocation without PBS.
    pub fn not_to(&self, input: Lwe<&[T]>, output: Lwe<&mut [T]>) {
        assert_dimension(input.as_view(), self.external_lwe_dimension.get());
        assert_dimension(output.as_view(), self.external_lwe_dimension.get());
        output.0.copy_from_slice(input.as_ref());
        self.not_assign(output);
    }

    fn not_assign(&self, mut ciphertext: Lwe<&mut [T]>) {
        let modulus = self.ciphertext_modulus;
        ciphertext.neg_assign(modulus);
        ciphertext.add_plaintext_assign(self.encoded_one, modulus);
    }

    /// Returns the backend PBS evaluator.
    #[must_use]
    #[inline]
    pub fn bootstrapper(&self) -> &E {
        &self.bootstrapper
    }

    /// Returns the backend PBS evaluator mutably.
    #[must_use]
    #[inline]
    pub fn bootstrapper_mut(&mut self) -> &mut E {
        &mut self.bootstrapper
    }

    /// Decomposes this evaluator into its backend PBS evaluator.
    #[must_use]
    #[inline]
    pub fn into_bootstrapper(self) -> E {
        self.bootstrapper
    }
}

fn prepare_binary_gate<T, M>(
    gate: BooleanGate,
    lhs: Lwe<&[T]>,
    rhs: Lwe<&[T]>,
    mut output: Lwe<&mut [T]>,
    modulus: M,
) where
    T: FheUint,
    M: RingContext<T>,
{
    assert_dimension(lhs.as_view(), output.dimension());
    assert_dimension(rhs.as_view(), output.dimension());

    match gate {
        BooleanGate::And | BooleanGate::Nand | BooleanGate::Or | BooleanGate::Nor => {
            lhs.add_to(&rhs, &mut output, modulus);
        }
        BooleanGate::Xor | BooleanGate::Xnor => {
            lhs.sub_to(&rhs, &mut output, modulus);
            output.mul_scalar_assign(T::TWO, modulus);
        }
    }
}

fn assert_dimension<T: FheUint>(ciphertext: Lwe<&[T]>, expected: usize) {
    assert_eq!(
        ciphertext.dimension(),
        expected,
        "Boolean LWE dimension mismatch"
    );
}
