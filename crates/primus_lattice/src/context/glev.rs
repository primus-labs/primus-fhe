use primus_integer::FheUint;

/// A working context for DCRT GLEV operations, holding temporary buffers for decomposition and recomposition.
pub struct DcrtGlevContext<T: FheUint> {
    adjust_big_uint_values: Vec<T>,
    decomposed_unsigned_values: Vec<T>,
    carries: Vec<bool>,
    multi_residues: Vec<T>,
    compose_buffer: Vec<T>,
}

/// A mutable reference view of [`DcrtGlevContext`] fields, used to borrow all buffers simultaneously.
pub struct DcrtGlevContextRefMut<'a, T: FheUint> {
    /// Buffer for big integer values adjusted during decomposition.
    pub adjust_big_uint_values: &'a mut [T],
    /// Buffer for unsigned decomposed values.
    pub decomposed_unsigned_values: &'a mut [T],
    /// Buffer tracking carries during decomposition.
    pub carries: &'a mut [bool],
    /// Buffer for multi-residue values after CRT decomposition.
    pub multi_residues: &'a mut [T],
    /// Buffer for composing values across moduli.
    pub compose_buffer: &'a mut [T],
}

impl<T: FheUint> DcrtGlevContext<T> {
    /// Creates a new [`DcrtGlevContext`] allocated for the given polynomial and modulus dimensions.
    pub fn new(
        poly_length: usize,
        crt_poly_len: usize,
        big_uint_poly_len: usize,
        moduli_count: usize,
    ) -> Self {
        Self {
            adjust_big_uint_values: vec![T::ZERO; big_uint_poly_len],
            decomposed_unsigned_values: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            multi_residues: vec![T::ZERO; crt_poly_len],
            compose_buffer: vec![T::ZERO; moduli_count],
        }
    }

    /// Returns a [`DcrtGlevContextRefMut`] that borrows all internal buffers mutably.
    #[inline]
    pub fn as_mut<'a>(&'a mut self) -> DcrtGlevContextRefMut<'a, T> {
        DcrtGlevContextRefMut {
            adjust_big_uint_values: &mut self.adjust_big_uint_values,
            decomposed_unsigned_values: &mut self.decomposed_unsigned_values,
            carries: &mut self.carries,
            multi_residues: &mut self.multi_residues,
            compose_buffer: &mut self.compose_buffer,
        }
    }

    /// Resets all buffers to their zero values.
    pub fn clear(&mut self) {
        self.adjust_big_uint_values.fill(T::ZERO);
        self.decomposed_unsigned_values.fill(T::ZERO);
        self.carries.fill(false);
        self.multi_residues.fill(T::ZERO);
        self.compose_buffer.fill(T::ZERO);
    }

    /// Returns a mutable reference to the compose buffer.
    pub fn compose_buffer_mut(&mut self) -> &mut [T] {
        &mut self.compose_buffer
    }
}
