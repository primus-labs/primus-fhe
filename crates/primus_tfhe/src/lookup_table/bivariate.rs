use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::{Modulus, ReduceAdd, RingContext};
use primus_shape::PolyLength;

use super::LookupTable;
use crate::{LookupTableError, Lwe};

/// A bounded two-input function evaluated by packing `z = x + B*y` before PBS.
///
/// The left input belongs to `0..B`, the right to `0..R`, and `B*R <= ceil(t/2)`.
/// Both use the same unsigned rounded input codec. This type binds the packing
/// base and modulus to a single-output LUT; it owns no keys or online scratch.
/// Pack into a reusable LWE with [`Self::pack_to`], then pass
/// [`Self::lookup_table`] to an ordinary programmable-bootstrap evaluator.
///
/// # Encoding and noise
///
/// With `E(m) = round(m*q/t)`, the packed phase is
/// `E(z) + e_x + B*e_y + rho(x,y)` modulo `q`, where
/// `rho(x,y) = E(x) + B*E(y) - E(x+B*y)`. This encoding discrepancy vanishes
/// when `t` divides `q`; in general `|rho| <= (B+2)/2` in ciphertext units.
/// It is additional noise, not a change to the LUT's input codec. The packed
/// error and any pre-BR key-switch error, followed by per-coefficient modulus
/// switching, must fit the LUT interval. Domain checks alone do not guarantee
/// that margin; the usual PBS output-noise requirements also apply.
#[derive(Clone, Debug)]
pub struct BivariateLookupTable<T: FheUint, M> {
    lookup_table: LookupTable<T>,
    base: usize,
    modulus: M,
}

impl<T: FheUint, M: RingContext<T>> BivariateLookupTable<T, M> {
    /// Compiles `function(x, y)` for `x < lhs_domain_len` and `y < rhs_domain_len`.
    ///
    /// The packing base is `lhs_domain_len`. Both lengths must be positive and
    /// their product must fit the input codec's front half. Polynomial capacity
    /// and rotation-center checks are inherited from [`LookupTable::try_new`].
    /// On success the callback runs once per pair, with `x` varying fastest.
    /// Unused input values are outside the compiled domain and are not passed to it.
    ///
    /// Outputs use unsigned `output_codec` encoding and must lie in its plaintext
    /// domain. Its ciphertext modulus must equal the input/accumulator modulus,
    /// as required by the current complete PBS chains. Decode the resulting
    /// external LWE phase with this output codec.
    pub fn try_new<OM, F>(
        lhs_domain_len: usize,
        rhs_domain_len: usize,
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, M>,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        OM: Modulus<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize, usize) -> T,
    {
        let input_domain_len = lhs_domain_len
            .checked_mul(rhs_domain_len)
            .filter(|&length| length != 0)
            .ok_or(LookupTableError::InvalidBivariateDomain {
                lhs_domain_len,
                rhs_domain_len,
            })?;
        let modulus = input_codec.ciphertext_modulus();
        if output_codec.ciphertext_modulus().explicit_value() != modulus.explicit_value() {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        let lookup_table = LookupTable::try_new(
            input_domain_len,
            poly_length,
            input_codec.plaintext_modulus(),
            modulus,
            modulus,
            |input| {
                let output = function(input % lhs_domain_len, input / lhs_domain_len);
                if output >= output_codec.plaintext_modulus() {
                    return Err(LookupTableError::OutputOutOfRange { input });
                }
                Ok(output_codec.encode_value(output, PlaintextEmbedding::Unsigned))
            },
        )?;
        Ok(Self {
            lookup_table,
            base: lhs_domain_len,
            modulus,
        })
    }

    /// Returns the left input's exclusive bound, also the packing base `B`.
    #[must_use]
    pub fn lhs_domain_len(&self) -> usize {
        self.base
    }

    /// Returns the right input's exclusive bound `R`.
    #[must_use]
    pub fn rhs_domain_len(&self) -> usize {
        self.lookup_table.input_domain_len() / self.base
    }

    /// Returns the LUT to apply to the packed ciphertext with ordinary PBS.
    #[must_use]
    pub fn lookup_table(&self) -> &LookupTable<T> {
        &self.lookup_table
    }

    /// Writes `lhs + B*rhs` modulo `q` into an existing LWE, without allocating.
    ///
    /// # Correctness
    ///
    /// Both ciphertexts must use the same external secret and dimension, and
    /// the unsigned input codec (including its modulus) supplied at construction.
    /// Coefficients must be canonical; plaintexts must lie in their respective
    /// domains. Only storage lengths are checked, not these semantics. Account
    /// for the combined error described on [`Self`] before applying PBS.
    ///
    /// # Panics
    ///
    /// Panics before writing if any ciphertext is missing its body or if the
    /// three coefficient lengths differ.
    pub fn pack_to(&self, lhs: Lwe<&[T]>, rhs: Lwe<&[T]>, mut output: Lwe<&mut [T]>) {
        let length = lhs.lwe_len();
        assert!(length != 0, "LWE ciphertext must include a body");
        assert_eq!(length, rhs.lwe_len(), "bivariate input dimensions differ");
        assert_eq!(length, output.lwe_len(), "packed output dimension differs");
        // Construction proves B <= B*R < t < q, so this cast and scalar are valid.
        self.modulus.reduce_mul_scalar_add_slice_to(
            rhs.as_ref(),
            T::as_from(self.base),
            lhs.as_ref(),
            output.as_mut(),
        );
    }
}
