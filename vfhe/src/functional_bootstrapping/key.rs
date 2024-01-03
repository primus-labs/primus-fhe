use algebra::{NTTField, Ring};
use lattice::{NTTRGSW, RLWE};

/// Bootstrapping key
#[derive(Debug, Clone)]
pub enum BootstrappingKey<F: NTTField> {
    /// TFHE binary bootstrapping key
    TFHEBinary(Vec<NTTRGSW<F>>),
    /// TFHE ternary bootstrapping key
    TFHETernary(Vec<(NTTRGSW<F>, NTTRGSW<F>)>),
}

impl<F: NTTField> BootstrappingKey<F> {
    /// Creates the TFHE binary bootstrapping key
    #[inline]
    pub fn binary_bootstrapping_key(key: Vec<NTTRGSW<F>>) -> Self {
        Self::TFHEBinary(key)
    }

    /// Creates the TFHE ternary bootstrapping key
    #[inline]
    pub fn ternary_bootstrapping_key(key: Vec<(NTTRGSW<F>, NTTRGSW<F>)>) -> Self {
        Self::TFHETernary(key)
    }

    /// Performs the bootstrapping operation
    pub fn bootstrapping<R: Ring>(
        &self,
        acc: RLWE<F>,
        a: &[R],
        nr: usize,
        nr2dq: usize,
    ) -> RLWE<F> {
        match self {
            BootstrappingKey::TFHEBinary(bk) => bk.iter().zip(a).fold(acc, |acc, (s_i, &a_i)| {
                // ACC = ACC + (Y^{-a_i} - 1) * ACC * RGSW(s_i)
                let median = s_i
                    .mul_with_rlwe(&acc)
                    .mul_with_monic_monomial_sub1(nr, nr2dq, -a_i);
                acc.add_element_wise(&median)
            }),
            BootstrappingKey::TFHETernary(bk) => {
                bk.iter().zip(a).fold(acc, |acc, (s_i, &a_i)| {
                    // u = 1
                    // ACC = ACC + (Y^{-a_i} - 1) * ACC * RGSW(s_i_u)
                    let median = s_i
                        .0
                        .mul_with_rlwe(&acc)
                        .mul_with_monic_monomial_sub1(nr, nr2dq, -a_i);
                    let acc = acc.add_element_wise(&median);

                    // u = -1
                    // ACC = ACC + (Y^{a_i} - 1) * ACC * RGSW(s_i_u)
                    let median = s_i
                        .1
                        .mul_with_rlwe(&acc)
                        .mul_with_monic_monomial_sub1(nr, nr2dq, a_i);
                    acc.add_element_wise(&median)
                })
            }
        }
    }
}
