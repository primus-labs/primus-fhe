use primus_integer::{BigUint, FheUint};
use primus_reduce::FieldContext;

use crate::{BaseConverter, RNSBase, RnsError};

use super::{HybridRNS, HybridRNSPartition, HybridRNSPartitioning};

impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates hybrid RNS precomputations for bases `Q` and `P`.
    ///
    /// `decomposition_count` (`dnum`) is the exact number of non-empty digits
    /// in this full `Q` basis. Each partition contains at most
    /// `partition_moduli_count` (`alpha`) moduli.
    ///
    /// # Errors
    ///
    /// Returns [`RnsError::InvalidDecompositionCount`] for `dnum == 0`,
    /// [`RnsError::IncompatibleDecompositionCount`] when fixed-size partitions
    /// cannot produce exactly `dnum` digits, and propagates invalid `Q`, `P`,
    /// or combined-basis errors from [`RNSBase`].
    pub fn new(
        q_moduli: &[M],
        p_moduli: &[M],
        decomposition_count: usize,
    ) -> Result<Self, RnsError> {
        let partitioning = HybridRNSPartitioning::new(q_moduli.len(), decomposition_count)?;
        Self::from_partitioning(q_moduli, p_moduli, partitioning)
    }

    /// Creates hybrid RNS precomputations for one active `Q` level using a
    /// partitioning rule derived from the full `Q` basis.
    ///
    /// Active levels must be ordered prefixes of the full basis used to create
    /// `partitioning`. This constructor validates the modulus count; the
    /// owner of the modulus chain is responsible for preserving the prefix.
    ///
    /// # Errors
    ///
    /// Returns [`RnsError::ActiveBaseTooLarge`] when `Q` exceeds the full-basis
    /// count in `partitioning`, and propagates invalid `Q`, `P`, or
    /// combined-basis errors from [`RNSBase`].
    pub fn from_partitioning(
        q_moduli: &[M],
        p_moduli: &[M],
        partitioning: HybridRNSPartitioning,
    ) -> Result<Self, RnsError> {
        if q_moduli.len() > partitioning.full_q_moduli_count() {
            return Err(RnsError::ActiveBaseTooLarge {
                actual: q_moduli.len(),
                maximum: partitioning.full_q_moduli_count(),
            });
        }

        let q_base = RNSBase::new(q_moduli)?;
        let p_base = RNSBase::new(p_moduli)?;
        let qp_base = q_base.extend_with(&p_base)?;

        let partition_moduli_count = partitioning.partition_moduli_count();
        let mut partitions = Vec::with_capacity(q_moduli.len().div_ceil(partition_moduli_count));

        for (partition_index, partition_moduli) in
            q_moduli.chunks(partition_moduli_count).enumerate()
        {
            let start = partition_index * partition_moduli_count;
            let end = start + partition_moduli.len();
            let partition_base = RNSBase::new(partition_moduli)?;
            let complement_moduli = q_moduli[..start]
                .iter()
                .chain(&q_moduli[end..])
                .chain(p_moduli)
                .copied()
                .collect();
            let complement_base = RNSBase::from_owned_moduli(complement_moduli)?;

            partitions.push(HybridRNSPartition {
                q_range: (start..end).into(),
                q_moduli_count: q_moduli.len(),
                mod_up_converter: BaseConverter::from_owned_bases(partition_base, complement_base),
            });
        }

        let BigUint(p) = p_base.moduli_product();

        let (p_mod_q, inv_p_mod_q) = q_moduli
            .iter()
            .map(|qi| {
                let p_mod_qi = qi.reduce(p);
                (p_mod_qi, qi.reduce_inv(p_mod_qi))
            })
            .collect();

        let mod_down_converter = BaseConverter::new(&p_base, &q_base);

        Ok(Self {
            q_base,
            p_base,
            qp_base,
            partitioning,
            partitions,
            p_mod_q,
            inv_p_mod_q,
            mod_down_converter,
        })
    }
}
