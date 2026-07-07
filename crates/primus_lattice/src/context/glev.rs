use primus_integer::FheUint;

pub struct DcrtGlevContext<T: FheUint> {
    adjust_big_uint_values: Vec<T>,
    decomposed_unsigned_values: Vec<T>,
    carries: Vec<bool>,
    multi_residues: Vec<T>,
    compose_buffer: Vec<T>,
}

pub struct DcrtGlevContextRefMut<'a, T: FheUint> {
    pub adjust_big_uint_values: &'a mut [T],
    pub decomposed_unsigned_values: &'a mut [T],
    pub carries: &'a mut [bool],
    pub multi_residues: &'a mut [T],
    pub compose_buffer: &'a mut [T],
}

impl<T: FheUint> DcrtGlevContext<T> {
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

    pub fn clear(&mut self) {
        self.adjust_big_uint_values.fill(T::ZERO);
        self.decomposed_unsigned_values.fill(T::ZERO);
        self.carries.fill(false);
        self.multi_residues.fill(T::ZERO);
        self.compose_buffer.fill(T::ZERO);
    }

    pub fn compose_buffer_mut(&mut self) -> &mut [T] {
        &mut self.compose_buffer
    }
}
