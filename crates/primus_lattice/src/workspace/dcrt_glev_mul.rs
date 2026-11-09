use primus_integer::FheUint;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::RnsGadgetSize;

/// Reusable workspace for DCRT GLev decomposition and recomposition.
///
/// # Correctness
///
/// Each operation initializes the buffers it uses; no reset is needed between
/// calls. A workspace may be reused with another parameter set when all required
/// workspace lengths match, as checked by [`Self::is_compatible`]. The workspace
/// stores the gadget size but does not bind the ordered RNS base, decomposition
/// basis, or DCRT table. Callers must ensure their mathematical compatibility.
/// Accumulating operations preserve the output and require it to be initialized.
pub struct DcrtGlevMulWorkspace<T: FheUint> {
    size: RnsGadgetSize,
    adjust_big_uint_values: Box<[T]>,
    decomposed_unsigned_values: Box<[T]>,
    carries: Box<[bool]>,
    multi_residues: Box<[T]>,
    compose_buffer: Box<[T]>,
}

/// A mutable reference view of [`DcrtGlevMulWorkspace`] fields, used to borrow all buffers simultaneously.
pub(crate) struct DcrtGlevMulWorkspaceRefMut<'a, T: FheUint> {
    /// Buffer for big integer values adjusted during decomposition.
    pub(crate) adjust_big_uint_values: &'a mut [T],
    /// Buffer for unsigned decomposed values.
    pub(crate) decomposed_unsigned_values: &'a mut [T],
    /// Buffer tracking carries during decomposition.
    pub(crate) carries: &'a mut [bool],
    /// Buffer for multi-residue values after CRT decomposition.
    pub(crate) multi_residues: &'a mut [T],
    /// Buffer for composing values across moduli.
    pub(crate) compose_buffer: &'a mut [T],
}

impl<T: FheUint> DcrtGlevMulWorkspace<T> {
    /// Creates reusable workspace for a checked RNS gadget layout and basis.
    ///
    /// # Panics
    ///
    /// Panics if the size and basis have different modulus counts.
    pub fn new<M>(size: RnsGadgetSize, rns_base: &RNSBase<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        let rns_glwe_size = size.rns_glwe_size();
        assert_eq!(
            rns_glwe_size.moduli_count(),
            rns_base.moduli_count(),
            "DCRT workspace size and RNS base must have equal modulus counts"
        );
        let poly_length = rns_glwe_size.poly_length().get();
        let big_uint_poly_len = poly_length * rns_base.big_uint_value_len();

        Self {
            size,
            adjust_big_uint_values: vec![T::ZERO; big_uint_poly_len].into_boxed_slice(),
            decomposed_unsigned_values: vec![T::ZERO; poly_length].into_boxed_slice(),
            carries: vec![false; poly_length].into_boxed_slice(),
            multi_residues: vec![T::ZERO; rns_glwe_size.rns_poly_len()].into_boxed_slice(),
            compose_buffer: vec![T::ZERO; rns_base.moduli_count()].into_boxed_slice(),
        }
    }

    /// Returns whether this workspace supports `size` and the basis limb width.
    ///
    /// Requires the bound gadget size and modulus count to match, along with
    /// the big-integer scratch length. Different modulus values are allowed;
    /// this does not validate the basis, DCRT table, or ciphertext representation.
    #[must_use]
    #[inline]
    pub fn is_compatible<M>(&self, size: RnsGadgetSize, rns_base: &RNSBase<T, M>) -> bool
    where
        M: FieldContext<T>,
    {
        let glwe_size = size.rns_glwe_size();
        self.size == size
            && glwe_size.moduli_count() == rns_base.moduli_count()
            && glwe_size
                .poly_length()
                .get()
                .checked_mul(rns_base.big_uint_value_len())
                == Some(self.adjust_big_uint_values.len())
    }

    /// Returns the RNS gadget sizes bound to this workspace.
    #[must_use]
    #[inline]
    pub fn size(&self) -> RnsGadgetSize {
        self.size
    }

    /// Returns a [`DcrtGlevMulWorkspaceRefMut`] that borrows all internal buffers mutably.
    #[inline]
    pub(crate) fn as_mut<'a>(&'a mut self) -> DcrtGlevMulWorkspaceRefMut<'a, T> {
        DcrtGlevMulWorkspaceRefMut {
            adjust_big_uint_values: &mut self.adjust_big_uint_values,
            decomposed_unsigned_values: &mut self.decomposed_unsigned_values,
            carries: &mut self.carries,
            multi_residues: &mut self.multi_residues,
            compose_buffer: &mut self.compose_buffer,
        }
    }
}
