use itertools::izip;
use primus_factor::FactorMul;
use primus_integer::AsInto;
use primus_integer::FheUint;
use primus_modulo::Modulo;
use primus_reduce::FieldContext;

use crate::RNSBase;

/// Precomputed converter between two RNS bases.
///
/// The converter owns cloned input and output bases and stores the matrix
/// `(Q / q_i) mod p_j`, where `q_i` are input-base moduli, `p_j` are output-base
/// moduli, and `Q` is the input-base product.
///
/// Batched conversion APIs take input and output residue arrays in modulus-major
/// layout. Their scratch buffer uses a different coefficient-major layout:
/// chunk `j` of length `input_moduli_count()` stores all adjusted input
/// residues for coefficient `j`.
#[derive(Clone)]
pub struct BaseConverter<T: FheUint, M: FieldContext<T>> {
    /// Source basis for incoming residues.
    input_base: RNSBase<T, M>,
    /// Destination basis for converted residues.
    output_base: RNSBase<T, M>,
    /// Row-major output-by-input base-change matrix.
    ///
    /// The slice length is `input_moduli_count() * output_moduli_count()`.
    /// Row `j` contains coefficients for output modulus `output_base.moduli()[j]`.
    base_change_matrix: Vec<T>,
}

impl<T: FheUint, M: FieldContext<T>> BaseConverter<T, M> {
    /// Creates a converter from `input_base` to `output_base`.
    ///
    /// The bases are cloned into the converter so the returned value can be
    /// used independently from the inputs. The precomputed matrix contains one
    /// row per output modulus and one column per input modulus.
    ///
    /// # Panics
    ///
    /// Panics if the base-change matrix length overflows `usize`.
    pub fn new(input_base: &RNSBase<T, M>, output_base: &RNSBase<T, M>) -> Self {
        let input_moduli_count = input_base.moduli_count();
        let output_moduli_count = output_base.moduli_count();

        assert!(
            input_moduli_count
                .checked_mul(output_moduli_count)
                .is_some(),
            "the len can not be too large!"
        );

        let mut base_change_matrix = vec![T::ZERO; input_moduli_count * output_moduli_count];

        for (row, &modulus) in base_change_matrix
            .chunks_exact_mut(input_moduli_count)
            .zip(output_base.moduli())
        {
            for (ele, m_i) in row.iter_mut().zip(input_base.iter_punctured_product()) {
                *ele = m_i.modulo(modulus);
            }
        }

        Self {
            input_base: input_base.clone(),
            output_base: output_base.clone(),
            base_change_matrix,
        }
    }

    /// Returns the input basis.
    pub fn input_base(&self) -> &RNSBase<T, M> {
        &self.input_base
    }

    /// Returns the output basis.
    pub fn output_base(&self) -> &RNSBase<T, M> {
        &self.output_base
    }

    /// Returns the number of moduli in the input basis.
    pub fn input_moduli_count(&self) -> usize {
        self.input_base.moduli_count()
    }

    /// Returns the number of moduli in the output basis.
    pub fn output_moduli_count(&self) -> usize {
        self.output_base.moduli_count()
    }

    /// Iterates over the output-by-input base-change matrix rows.
    ///
    /// The iterator yields `output_moduli_count()` rows. Each row has
    /// `input_moduli_count()` entries and corresponds to one output modulus.
    fn iter_base_change_matrix(&self) -> std::slice::ChunksExact<'_, T> {
        self.base_change_matrix
            .chunks_exact(self.input_moduli_count())
    }

    /// Converts one residue vector from the input basis to the output basis.
    ///
    /// `residues_in.len()` must equal `input_moduli_count()`. Element `i` is
    /// interpreted modulo `input_base().moduli()[i]`.
    ///
    /// `residues_out.len()` must equal `output_moduli_count()`. Element `j`
    /// receives the converted residue modulo `output_base().moduli()[j]`.
    ///
    /// `scratch.len()` must equal `input_moduli_count()`. It stores the
    /// adjusted input residues and is overwritten by the conversion.
    pub fn fast_convert(&self, residues_in: &[T], residues_out: &mut [T], scratch: &mut [T]) {
        debug_assert_eq!(residues_in.len(), self.input_moduli_count());
        debug_assert_eq!(scratch.len(), self.input_moduli_count());
        debug_assert_eq!(residues_out.len(), self.output_moduli_count());

        izip!(
            residues_in,
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli(),
            scratch.iter_mut()
        )
        .for_each(|(&value, &inv, modulus, result)| {
            *result = inv.factor_mul_modulo(value, unsafe { modulus.value_unchecked() });
        });

        let buf = &*scratch;

        izip!(
            residues_out,
            self.iter_base_change_matrix(),
            self.output_base.moduli()
        )
        .for_each(|(ele, base_change_row, modulus)| {
            *ele = modulus.reduce_dot_product(buf, base_change_row);
        });
    }

    /// Fills the coefficient-major scratch buffer for batched fast conversion.
    ///
    /// `crt_poly_in.len()` must equal `input_moduli_count() * poly_length` and
    /// uses modulus-major input layout. `scratch.len()` must be the same, but
    /// the written layout is coefficient-major: chunk `j` of length
    /// `input_moduli_count()` stores all adjusted residues for coefficient `j`.
    fn fill_fast_convert_array_scratch(
        &self,
        crt_poly_in: &[T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let input_moduli_count = self.input_moduli_count();
        debug_assert_eq!(crt_poly_in.len(), input_moduli_count * poly_length);
        debug_assert_eq!(scratch.len(), input_moduli_count * poly_length);

        izip!(
            crt_poly_in.chunks_exact(poly_length),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli()
        )
        .enumerate()
        .for_each(
            |(i, (poly, &inv_punctured_product_mod_modulus, &modulus))| {
                if inv_punctured_product_mod_modulus.value().is_one() {
                    izip!(poly, scratch.iter_mut().skip(i).step_by(input_moduli_count)).for_each(
                        |(&x, ele)| {
                            *ele = x.modulo(modulus);
                        },
                    );
                } else {
                    let modulus = unsafe { modulus.value_unchecked() };
                    izip!(poly, scratch.iter_mut().skip(i).step_by(input_moduli_count)).for_each(
                        |(&x, ele)| {
                            *ele = inv_punctured_product_mod_modulus.factor_mul_modulo(x, modulus);
                        },
                    );
                }
            },
        );
    }

    /// Converts a modulus-major array of residue vectors between bases.
    ///
    /// `crt_poly_in.len()` must equal `input_moduli_count() * poly_length` and
    /// uses modulus-major layout: chunk `i` of length `poly_length` stores all
    /// coefficients modulo `input_base().moduli()[i]`.
    ///
    /// `crt_poly_out.len()` must equal `output_moduli_count() * poly_length`
    /// and is written in the same modulus-major layout for the output basis.
    ///
    /// `scratch.len()` must equal `input_moduli_count() * poly_length`. It is
    /// overwritten in coefficient-major layout before the output chunks are
    /// computed.
    pub fn fast_convert_array(
        &self,
        crt_poly_in: &[T],
        crt_poly_out: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let input_moduli_count = self.input_moduli_count();
        let expected_out_len = self
            .output_moduli_count()
            .checked_mul(poly_length)
            .expect("RNS output length overflow");

        assert_eq!(crt_poly_out.len(), expected_out_len);
        self.fill_fast_convert_array_scratch(crt_poly_in, poly_length, scratch);

        izip!(
            crt_poly_out.chunks_exact_mut(poly_length),
            self.iter_base_change_matrix(),
            self.output_base.moduli()
        )
        .for_each(|(poly, inv_punctured_product_mod_modulus, modulus)| {
            izip!(poly, scratch.chunks_exact(input_moduli_count)).for_each(|(ele, product)| {
                *ele = modulus.reduce_dot_product(product, inv_punctured_product_mod_modulus);
            });
        });
    }

    /// Converts an array and returns output residues as pairs.
    ///
    /// The output basis must contain exactly two moduli. `crt_poly_in.len()`
    /// must equal `input_moduli_count() * poly_length` and uses modulus-major
    /// layout.
    ///
    /// `scratch.len()` must equal `input_moduli_count() * poly_length`. It is
    /// overwritten in coefficient-major layout and is borrowed by the returned
    /// iterator.
    ///
    /// The iterator yields exactly `poly_length` items, one `(mod p_0, mod p_1)`
    /// pair per coefficient.
    pub fn fast_convert_array_to_pair_iter<'a>(
        &'a self,
        crt_poly_in: &[T],
        poly_length: usize,
        scratch: &'a mut [T],
    ) -> impl Iterator<Item = (T, T)> + 'a {
        assert_eq!(
            self.output_moduli_count(),
            2,
            "output base in fast_convert_array_to_pair must contain exactly two moduli"
        );

        let input_moduli_count = self.input_moduli_count();
        self.fill_fast_convert_array_scratch(crt_poly_in, poly_length, scratch);

        let mut rows = self.iter_base_change_matrix();
        let row_0 = rows.next().expect("missing first output-base row");
        let row_1 = rows.next().expect("missing second output-base row");
        let modulus_0 = self.output_base.moduli()[0];
        let modulus_1 = self.output_base.moduli()[1];

        scratch
            .chunks_exact(input_moduli_count)
            .map(move |product| {
                (
                    modulus_0.reduce_dot_product(product, row_0),
                    modulus_1.reduce_dot_product(product, row_1),
                )
            })
    }

    /// Exactly converts an input-basis array to a single-modulus output basis.
    ///
    /// The output basis must contain exactly one modulus. `crt_poly_in.len()`
    /// must equal `input_moduli_count() * poly_length` and uses modulus-major
    /// layout.
    ///
    /// `crt_poly_out.len()` must equal `poly_length`; it receives one residue
    /// modulo the single output modulus for each coefficient.
    ///
    /// This uses the floating-point correction term common in exact RNS base
    /// conversion.
    pub fn exact_convert_array(
        &self,
        crt_poly_in: &[T],
        crt_poly_out: &mut [T],
        poly_length: usize,
    ) {
        let input_moduli_count = self.input_moduli_count();
        debug_assert_eq!(crt_poly_in.len(), input_moduli_count * poly_length);
        debug_assert_eq!(crt_poly_out.len(), poly_length);

        assert_eq!(
            self.output_moduli_count(),
            1,
            "output base in exact_convert_array must be one."
        );

        let mut temp: Vec<T> = vec![T::ZERO; input_moduli_count * poly_length];
        let mut v: Vec<f64> = vec![0.0f64; input_moduli_count * poly_length];
        let mut aggregated_rounded_v: Vec<T> = vec![T::ZERO; poly_length];

        // Calculate [x_{i} * \hat{q_{i}}]_{q_{i}}
        izip!(
            crt_poly_in.chunks_exact(poly_length),
            self.input_base.inv_punctured_product_mod_modulus(),
            self.input_base.moduli()
        )
        .enumerate()
        .for_each(
            |(i, (poly, &inv_punctured_product_mod_modulus, &modulus))| {
                let divisor: f64 = unsafe { modulus.value_unchecked().as_into() };
                if inv_punctured_product_mod_modulus.value().is_one() {
                    // No multiplication needed
                    izip!(
                        poly,
                        temp.iter_mut().skip(i).step_by(input_moduli_count),
                        v.iter_mut().skip(i).step_by(input_moduli_count)
                    )
                    .for_each(|(&x, ele, fele)| {
                        // Reduce modulo input_base element
                        *ele = x.modulo(modulus);
                        let dividend: f64 = (*ele).as_into();
                        *fele = dividend / divisor;
                    });
                } else {
                    // Multiplication needed
                    izip!(
                        poly,
                        temp.iter_mut().skip(i).step_by(input_moduli_count),
                        v.iter_mut().skip(i).step_by(input_moduli_count)
                    )
                    .for_each(|(&x, ele, fele)| {
                        // Multiply coefficient of in with input-base inverse punctured-product element

                        *ele = inv_punctured_product_mod_modulus
                            .factor_mul_modulo(x, unsafe { modulus.value_unchecked() });
                        let dividend: f64 = (*ele).as_into();
                        *fele = dividend / divisor;
                    });
                }
            },
        );

        // Aggregate v and round to the nearest integer.
        izip!(
            v.chunks_exact(input_moduli_count),
            aggregated_rounded_v.iter_mut()
        )
        .for_each(|(vi, ri)| {
            // Otherwise a memory space of the last execution will be used.
            let aggregated_v: f64 = vi.iter().sum();
            *ri = (aggregated_v + 0.5).as_into();
        });

        let p = self.output_base.moduli()[0];
        let q_mod_p = self.input_base.moduli_product().0.modulo(p);
        let base_change_matrix_first = self.iter_base_change_matrix().next().unwrap();

        // Final multiplication
        izip!(
            crt_poly_out,
            temp.chunks_exact(input_moduli_count),
            aggregated_rounded_v,
        )
        .for_each(|(coeff, b, v)| {
            // Compute the base conversion sum modulo output_base element
            let sum_mod_output_base = p.reduce_dot_product(b, base_change_matrix_first);
            // Minus v*[q]_{p} mod p
            let v_q_mod_p = p.reduce_mul(v, q_mod_p);
            *coeff = p.reduce_sub(sum_mod_output_base, v_q_mod_p);
        });
    }
}
