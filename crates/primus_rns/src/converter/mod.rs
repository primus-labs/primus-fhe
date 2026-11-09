mod corrected;
mod fast;
pub use corrected::CorrectedConversionWorkspace;
pub(crate) use fast::FastConversionLimb;

use primus_integer::FheUint;
use primus_reduce::FieldContext;

use crate::RNSBase;

/// Precomputation selected from the source-base shape.
///
/// For a one-modulus source base, both the inverse punctured product and every
/// base-change matrix entry are one. Storing the general matrix in that case
/// would only allocate a vector of ones and route conversion through
/// one-element dot products.
#[derive(Clone)]
enum BaseConversionKernel<T> {
    SingleInput,
    General { base_change_matrix: Vec<T> },
}

/// Precomputed converter between two RNS bases.
///
/// The converter owns input and output base handles, sharing their immutable
/// CRT precomputations with other handles. A multi-modulus source
/// stores the matrix `(Q / q_i) mod p_j`, where `q_i` are input-base moduli,
/// `p_j` are output-base moduli, and `Q` is the input-base product. A
/// one-modulus source uses a direct-reduction kernel and stores no matrix.
///
/// # Arithmetic context
///
/// RNS conversion uses [`primus_modulus::BarrettModulus`] (or derived Barrett).
/// Its modulus bounds already guarantee the two spare operand bits required by
/// cross-modulus dot products. No additional range validation is needed here:
/// source residues are assumed canonical for their own moduli. A custom `M`
/// must satisfy the numerical requirements of [`Self::fast_convert`];
/// [`FieldContext`] alone does not establish them.
///
/// # Fast conversion semantics
///
/// Let `a_i` be the input residues and define
/// `u_i = [a_i (Q / q_i)^(-1)] mod q_i`. For an input base with more than one
/// modulus, the [`Self::fast_convert`], [`Self::fast_convert_array`], and
/// [`Self::fast_convert_array_to_pair_iter`] methods compute
///
/// ```text
/// y_j = [sum_i u_i (Q / q_i)] mod p_j = [x + kQ] mod p_j
/// ```
///
/// for some integer `k`, where `x` has residues `a_i` in the input base. These
/// methods omit the quotient correction needed to select the canonical lift of
/// `x`, so `y_j` is not generally equal to `x mod p_j`. This SEAL-style
/// approximate conversion is intended for algorithms such as Hybrid ModDown
/// that cancel the multiple-of-`Q` term. For a one-modulus input base, the
/// specialized kernel directly reduces the input residue and is exact.
///
/// Batched conversion APIs take input and output residue arrays in modulus-major
/// layout. Their scratch buffer uses a different value-major layout:
/// chunk `j` of length `input_moduli_count()` stores all adjusted input
/// residues for value `j`.
#[derive(Clone)]
pub struct BaseConverter<T: FheUint, M: FieldContext<T>> {
    /// Source basis for incoming residues.
    input_base: RNSBase<T, M>,
    /// Destination basis for converted residues.
    output_base: RNSBase<T, M>,
    kernel: BaseConversionKernel<T>,
}

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Creates a converter from references, sharing both bases' precomputations.
    /// The conversion matrix is prepared separately for this ordered pair.
    ///
    /// See [`from_owned_bases`](Self::from_owned_bases) for the owned variant.
    #[must_use]
    pub fn new(input_base: &RNSBase<T, M>, output_base: &RNSBase<T, M>) -> Self {
        Self::from_owned_bases(input_base.clone(), output_base.clone())
    }

    /// Creates a converter from owned bases.
    ///
    /// Moves `input_base` and `output_base`, avoiding the two Arc reference-count
    /// increments of [`Self::new`]. Both constructors share existing base tables;
    /// only the conversion-specific matrix is allocated for a multi-modulus source.
    ///
    /// # Panics
    ///
    /// Panics if the base-change matrix length overflows `usize`.
    #[must_use]
    pub fn from_owned_bases(input_base: RNSBase<T, M>, output_base: RNSBase<T, M>) -> Self {
        let input_moduli_count = input_base.moduli_count();
        let output_moduli_count = output_base.moduli_count();

        assert!(
            input_moduli_count
                .checked_mul(output_moduli_count)
                .is_some(),
            "RNS base-change matrix length overflow"
        );

        let kernel = if input_moduli_count == 1 {
            BaseConversionKernel::SingleInput
        } else {
            let mut base_change_matrix = vec![T::ZERO; input_moduli_count * output_moduli_count];

            for (row, &pj) in base_change_matrix
                .chunks_exact_mut(input_moduli_count)
                .zip(output_base.moduli())
            {
                for (q_div_qi_mod_pj, q_div_qi) in
                    row.iter_mut().zip(input_base.iter_punctured_product())
                {
                    *q_div_qi_mod_pj = pj.reduce(q_div_qi.digits());
                }
            }

            BaseConversionKernel::General { base_change_matrix }
        };

        Self {
            input_base,
            output_base,
            kernel,
        }
    }

    /// Returns the number of moduli in the input basis.
    #[must_use]
    pub fn input_moduli_count(&self) -> usize {
        self.input_base.moduli_count()
    }

    /// Returns the number of moduli in the output basis.
    #[must_use]
    pub fn output_moduli_count(&self) -> usize {
        self.output_base.moduli_count()
    }

    /// Iterates over the output-by-input base-change matrix rows.
    ///
    /// The iterator yields `output_moduli_count()` rows. Each row has
    /// `input_moduli_count()` entries and corresponds to one output modulus.
    ///
    /// # Panics
    ///
    /// Panics when called for the single-input kernel, which has no matrix.
    fn iter_base_change_matrix(&self) -> std::slice::ChunksExact<'_, T> {
        let base_change_matrix = match &self.kernel {
            BaseConversionKernel::SingleInput => {
                panic!("single-input base conversion has no base-change matrix")
            }
            BaseConversionKernel::General { base_change_matrix } => base_change_matrix,
        };
        base_change_matrix.chunks_exact(self.input_moduli_count())
    }

    #[inline]
    fn uses_single_input_kernel(&self) -> bool {
        matches!(&self.kernel, BaseConversionKernel::SingleInput)
    }
}
