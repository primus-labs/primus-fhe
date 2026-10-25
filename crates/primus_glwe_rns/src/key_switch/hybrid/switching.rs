use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::DcrtPolynomial;
use primus_reduce::FieldContext;
use primus_rns::HybridRNS;

use super::{HybridRnsGlweKeySwitchingKey, mod_down::approx_mod_down_ntt};
use crate::parameter::validate_moduli;
use crate::{DcrtGlweCiphertext, HybridRnsKeySwitchDomain, RnsDomainError};

#[cfg(test)]
use crate::CrtGlweCiphertext;

impl<T: FheUint> HybridRnsGlweKeySwitchingKey<T> {
    fn accumulate_ntt_mask<M, Table>(
        &self,
        mask_mod_q_ntt: &[T],
        key_for_secret: &[T],
        hybrid_rns: &HybridRNS<T, M>,
        table: &DcrtTable<Table>,
        workspace: &mut HybridRnsGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = self.input_size.poly_length().get();
        let q_moduli_count = self.input_size.moduli_count();
        let qp_poly_len = self.qp_size.rns_poly_len();
        let qp_glwe_len = self.qp_size.rns_glwe_len();
        let HybridRnsGlweKeySwitchingWorkspace {
            accumulator_qp,
            q_scratch,
            mod_up_limb,
            mod_up_scratch,
            ..
        } = workspace;

        q_scratch.copy_from_slice(mask_mod_q_ntt);
        table.ntt_tables()[..q_moduli_count]
            .iter()
            .zip(q_scratch.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, q_limb)| ntt_table.inverse_transform_slice(q_limb));

        let qp_moduli = hybrid_rns.qp_base().moduli();
        for (partition, key_glwe) in hybrid_rns
            .partitions()
            .zip(key_for_secret.chunks_exact(qp_glwe_len))
        {
            for modulus_index in partition.q_range() {
                let limb_start = modulus_index * poly_length;
                add_qp_glwe_product(
                    accumulator_qp,
                    key_glwe,
                    &mask_mod_q_ntt[limb_start..limb_start + poly_length],
                    qp_poly_len,
                    modulus_index,
                    &qp_moduli[modulus_index],
                );
            }

            let scratch_len = partition.mod_up_scratch_len(poly_length);
            partition.for_each_approx_mod_up_complement_limb(
                q_scratch,
                mod_up_limb,
                poly_length,
                &mut mod_up_scratch[..scratch_len],
                |modulus_index, converted_limb| {
                    table.ntt_tables()[modulus_index].transform_slice(converted_limb);
                    add_qp_glwe_product(
                        accumulator_qp,
                        key_glwe,
                        converted_limb,
                        qp_poly_len,
                        modulus_index,
                        &qp_moduli[modulus_index],
                    );
                },
            );
        }
    }

    /// Reduces each QP accumulator polynomial in place, copies its Q limbs to
    /// the complete output, then negates it. All key/domain/workspace layouts and
    /// numerical representations have been established by the caller.
    fn mod_down_and_write_negated_accumulator<M, Table>(
        &self,
        mut c_out: DcrtGlweCiphertext<&mut [T]>,
        hybrid_rns: &HybridRNS<T, M>,
        table: &DcrtTable<Table>,
        workspace: &mut HybridRnsGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = self.input_size.poly_length().get();
        let qp_poly_len = self.qp_size.rns_poly_len();
        let q_poly_len = self.output_size.rns_poly_len();

        for accumulator in workspace.accumulator_qp.chunks_exact_mut(qp_poly_len) {
            approx_mod_down_ntt(
                hybrid_rns,
                table,
                accumulator,
                poly_length,
                &mut workspace.q_scratch,
                &mut workspace.mod_down_scratch,
            );
        }

        let (accumulator_mask, accumulator_body) = workspace
            .accumulator_qp
            .split_at(self.qp_size.rns_mask_len());
        let (a_out, b_out) = c_out.a_b_mut_slices(q_poly_len);
        for (output, accumulator) in a_out
            .chunks_exact_mut(q_poly_len)
            .zip(accumulator_mask.chunks_exact(qp_poly_len))
        {
            output.copy_from_slice(&accumulator[..q_poly_len]);
        }
        b_out.copy_from_slice(&accumulator_body[..q_poly_len]);
        c_out.neg_assign(poly_length, q_poly_len, hybrid_rns.q_base().moduli());
    }

    /// Uses the evaluator's established key/domain/workspace binding. Operand layouts
    /// and representation remain caller contracts; no numerical rebinding occurs here.
    fn key_switch_kernel_to<M, Table>(
        &self,
        c_in: DcrtGlweCiphertext<&[T]>,
        mut c_out: DcrtGlweCiphertext<&mut [T]>,
        domain: &HybridRnsKeySwitchDomain<'_, T, M, Table>,
        workspace: &mut HybridRnsGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let hybrid_rns = domain.hybrid_rns();
        let table = domain.table();
        let qp_gadget_len = self.qp_gadget_len;
        let (mask_in, body_in) = c_in.a_b(self.input_size.rns_poly_len());

        workspace.accumulator_qp.fill(T::ZERO);
        for (mask_polynomial, key_for_secret) in mask_in.zip(self.key.chunks_exact(qp_gadget_len)) {
            self.accumulate_ntt_mask(
                mask_polynomial.as_slice(),
                key_for_secret,
                hybrid_rns,
                table,
                workspace,
            );
        }

        self.mod_down_and_write_negated_accumulator(
            c_out.as_mut_view(),
            hybrid_rns,
            table,
            workspace,
        );
        let (_, b_out) = c_out.a_b_mut_slices(self.output_size.rns_poly_len());
        DcrtPolynomial(b_out).add_assign(
            &body_in,
            self.input_size.poly_length().get(),
            hybrid_rns.q_base().moduli(),
        );
    }

    /// Coefficient-domain oracle retaining full ModUp and message transforms.
    /// Consumes test operands with the same complete key/domain/workspace layouts.
    #[cfg(test)]
    fn key_switch_coeff_reference_to<M, Table>(
        &self,
        c_in: CrtGlweCiphertext<&[T]>,
        mut c_out: DcrtGlweCiphertext<&mut [T]>,
        domain: &HybridRnsKeySwitchDomain<'_, T, M, Table>,
        workspace: &mut HybridRnsGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let hybrid_rns = domain.hybrid_rns();
        let table = domain.table();
        let poly_length = self.input_size.poly_length().get();
        let qp_poly_len = self.qp_size.rns_poly_len();
        let qp_glwe_len = self.qp_size.rns_glwe_len();
        let qp_gadget_len = self.qp_gadget_len;
        let (mask_in, body_in) = c_in.a_b(self.input_size.rns_poly_len());
        let qp_moduli = hybrid_rns.qp_base().moduli();
        let mut digit_qp = vec![T::ZERO; qp_poly_len];

        workspace.accumulator_qp.fill(T::ZERO);
        for (mask_polynomial, key_for_secret) in mask_in.zip(self.key.chunks_exact(qp_gadget_len)) {
            for (partition, key_glwe) in hybrid_rns
                .partitions()
                .zip(key_for_secret.chunks_exact(qp_glwe_len))
            {
                let scratch_len = partition.mod_up_scratch_len(poly_length);
                partition.approx_mod_up_to(
                    mask_polynomial.as_slice(),
                    &mut digit_qp,
                    poly_length,
                    &mut workspace.mod_up_scratch[..scratch_len],
                );
                table.transform_slice(&mut digit_qp);

                for (accumulator_poly, key_poly) in workspace
                    .accumulator_qp
                    .chunks_exact_mut(qp_poly_len)
                    .zip(key_glwe.chunks_exact(qp_poly_len))
                {
                    let mut accumulator_poly = DcrtPolynomial(accumulator_poly);
                    accumulator_poly.add_mul_assign(
                        &DcrtPolynomial(digit_qp.as_slice()),
                        &DcrtPolynomial(key_poly),
                        poly_length,
                        qp_moduli,
                    );
                }
            }
        }

        self.mod_down_and_write_negated_accumulator(
            c_out.as_mut_view(),
            hybrid_rns,
            table,
            workspace,
        );
        workspace.q_scratch.copy_from_slice(body_in.as_slice());
        table.ntt_tables()[..self.input_size.moduli_count()]
            .iter()
            .zip(workspace.q_scratch.chunks_exact_mut(poly_length))
            .for_each(|(ntt_table, q_limb)| ntt_table.transform_slice(q_limb));
        let (_, b_out) = c_out.a_b_mut_slices(self.output_size.rns_poly_len());
        DcrtPolynomial(b_out).add_assign(
            &DcrtPolynomial(workspace.q_scratch.as_slice()),
            poly_length,
            hybrid_rns.q_base().moduli(),
        );
    }
}

#[inline]
fn add_qp_glwe_product<T, M>(
    accumulator_qp: &mut [T],
    key_glwe: &[T],
    digit_limb: &[T],
    qp_poly_len: usize,
    modulus_index: usize,
    modulus: &M,
) where
    T: FheUint,
    M: FieldContext<T>,
{
    let limb_start = modulus_index * digit_limb.len();
    let limb_end = limb_start + digit_limb.len();
    for (accumulator_poly, key_poly) in accumulator_qp
        .chunks_exact_mut(qp_poly_len)
        .zip(key_glwe.chunks_exact(qp_poly_len))
    {
        modulus.reduce_add_mul_slice_assign(
            &mut accumulator_poly[limb_start..limb_end],
            digit_limb,
            &key_poly[limb_start..limb_end],
        );
    }
}

/// Hybrid RNS key switching bound to its key, Q/P domain and owned workspace.
///
/// The constructor checks modulus order, Q/P split and partition width once.
/// Ciphertext secret identity and NTT representation remain caller contracts.
pub struct HybridRnsGlweKeySwitchEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a HybridRnsGlweKeySwitchingKey<T>,
    domain: &'a HybridRnsKeySwitchDomain<'a, T, M, Table>,
    workspace: HybridRnsGlweKeySwitchingWorkspace<T>,
}

impl<'a, T, M, Table> HybridRnsGlweKeySwitchEvaluator<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Creates a new [`HybridRnsGlweKeySwitchEvaluator`] for a compatible key and domain.
    ///
    /// # Panics
    /// Panics if [`Self::try_new`] rejects the binding.
    #[must_use]
    pub fn new(
        key: &'a HybridRnsGlweKeySwitchingKey<T>,
        domain: &'a HybridRnsKeySwitchDomain<'a, T, M, Table>,
    ) -> Self {
        Self::try_new(key, domain)
            .unwrap_or_else(|error| panic!("invalid hybrid key-switch binding: {error}"))
    }

    /// Binds the key and domain before allocating reusable scratch.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for a different polynomial length, ordered
    /// Q/P basis, Q/P split or partition width.
    pub fn try_new(
        key: &'a HybridRnsGlweKeySwitchingKey<T>,
        domain: &'a HybridRnsKeySwitchDomain<'a, T, M, Table>,
    ) -> Result<Self, RnsDomainError<T>> {
        let expected = key.input_size.poly_length().get();
        let actual = domain.table().poly_length().get();
        if expected != actual {
            return Err(RnsDomainError::PolynomialLengthMismatch { expected, actual });
        }
        let hybrid_rns = domain.hybrid_rns();
        validate_moduli(
            key.qp_moduli.iter().copied(),
            hybrid_rns.qp_base().moduli().iter().map(|m| m.value()),
        )?;
        let expected = key.input_size.moduli_count();
        let actual = hybrid_rns.q_moduli_count();
        if expected != actual {
            return Err(RnsDomainError::ModuliCountMismatch { expected, actual });
        }
        let expected = key.partition_moduli_count;
        let actual = hybrid_rns.partition_moduli_count();
        if expected != actual {
            return Err(RnsDomainError::PartitionWidthMismatch { expected, actual });
        }
        let workspace = HybridRnsGlweKeySwitchingWorkspace {
            accumulator_qp: vec![T::ZERO; key.qp_size.rns_glwe_len()],
            q_scratch: vec![T::ZERO; key.input_size.rns_poly_len()],
            mod_up_limb: vec![T::ZERO; key.input_size.poly_length().get()],
            mod_up_scratch: vec![
                T::ZERO;
                hybrid_rns
                    .max_mod_up_scratch_len(key.input_size.poly_length().get())
            ],
            mod_down_scratch: vec![
                T::ZERO;
                hybrid_rns
                    .mod_down_scratch_len(key.input_size.poly_length().get())
            ],
        };
        Ok(Self {
            key,
            domain,
            workspace,
        })
    }

    /// Switches a DCRT Q-basis input to a DCRT Q-basis output, overwriting it.
    ///
    /// Each mask is inverse-transformed once for cross-modulus conversion;
    /// partition-owned limbs and the body are consumed directly in NTT form.
    ///
    /// # Correctness
    /// Input/output use the key's complete layouts, input secret and NTT representation.
    pub fn key_switch_to<A: Data<Elem = T>, B: DataMut<Elem = T>>(
        &mut self,
        input: &DcrtGlweCiphertext<A>,
        output: &mut DcrtGlweCiphertext<B>,
    ) {
        debug_assert_eq!(input.as_ref().len(), self.key.input_size.rns_glwe_len());
        debug_assert_eq!(output.as_ref().len(), self.key.output_size.rns_glwe_len());
        self.key.key_switch_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            self.domain,
            &mut self.workspace,
        );
    }
}

/// Scratch overwritten by each switch; its numerical binding belongs to the evaluator.
struct HybridRnsGlweKeySwitchingWorkspace<T: FheUint> {
    accumulator_qp: Vec<T>,
    // One coefficient-domain Q polynomial, also reused for mixed ModDown output.
    q_scratch: Vec<T>,
    // One streamed coefficient-domain ModUp limb before its forward NTT.
    mod_up_limb: Vec<T>,
    mod_up_scratch: Vec<T>,
    mod_down_scratch: Vec<T>,
}

#[cfg(test)]
mod tests {
    use primus_lattice::GlweDimension;
    use primus_lattice::glwe::DcrtGlwe;
    use primus_modulus::BarrettModulus;
    use primus_ntt::UintDcrtTable;
    use primus_poly::Polynomial;
    use primus_shape::PolyLength;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
    };

    #[test]
    fn coefficient_and_ntt_hybrid_key_switch_match() {
        type Value = u64;

        let dimension = 2;
        // Small ring; three Q limbs retain wide arithmetic and an uneven partition.
        let poly_length = PolyLength::new(32);
        let plaintext_modulus = BarrettModulus::new(12289);
        let gamma = BarrettModulus::new(2305843009213554689);
        let q_moduli =
            [1125899906826241, 1125899906629633, 1125899906031617].map(BarrettModulus::new);
        let p_moduli = [1125899905036289].map(BarrettModulus::new);
        let qp_moduli: Vec<_> = q_moduli.iter().chain(&p_moduli).copied().collect();
        let q_table = UintDcrtTable::new(poly_length, &q_moduli).unwrap();
        let qp_table = UintDcrtTable::new(poly_length, &qp_moduli).unwrap();
        let parameters = CrtGlweParameters::new(
            GlweDimension::new(dimension),
            poly_length,
            plaintext_modulus,
            gamma,
            &q_moduli,
            SecretKeyDistr::SparseTernary,
            3.20,
        );
        let hybrid = HybridRNS::new(&q_moduli, &p_moduli, 2).unwrap();
        let domain = HybridRnsKeySwitchDomain::try_new(&hybrid, &qp_table).unwrap();
        let mut rng = StdRng::seed_from_u64(0x4859_4252_4944);
        let input_key = GlweSecretKey::generate(
            parameters.size().glwe_size(),
            parameters.secret_key_sampler(),
            &mut rng,
        );
        let output_key = GlweSecretKey::generate(
            parameters.size().glwe_size(),
            parameters.secret_key_sampler(),
            &mut rng,
        );
        let input_dcrt_key = DcrtGlweSecretKey::from_coeff_secret_key(&input_key, &q_table);
        let switching_key = HybridRnsGlweKeySwitchingKey::generate(
            &input_key,
            parameters.encryption_parameters(),
            &output_key,
            &domain,
            &mut rng,
        );

        let plaintext: Polynomial<Vec<Value>> =
            Polynomial::random(poly_length.get(), plaintext_modulus, &mut rng);
        let mut input: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let input_dcrt_key_context = input_dcrt_key.try_bind(&parameters, &q_table).unwrap();
        input_dcrt_key_context.encrypt_to(&plaintext, &mut input, &mut rng);
        let input_coeff = input.clone().into_coeff_form(&q_table);
        let mut from_ntt: DcrtGlwe<Vec<Value>> =
            DcrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let mut from_coeff: DcrtGlwe<Vec<Value>> =
            DcrtGlweCiphertext::zero(parameters.rns_glwe_len());
        let mut ntt_evaluator = HybridRnsGlweKeySwitchEvaluator::new(&switching_key, &domain);
        let mut coeff_evaluator = HybridRnsGlweKeySwitchEvaluator::new(&switching_key, &domain);

        ntt_evaluator.key_switch_to(&input, &mut from_ntt);
        switching_key.key_switch_coeff_reference_to(
            input_coeff.as_view(),
            from_coeff.as_mut_view(),
            &domain,
            &mut coeff_evaluator.workspace,
        );

        assert_eq!(from_ntt.as_ref(), from_coeff.as_ref());
    }
}
