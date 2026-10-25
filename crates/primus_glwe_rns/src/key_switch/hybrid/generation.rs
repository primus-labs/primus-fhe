use primus_distr::{sample_crt_gaussian_values_to, sample_crt_uniform_values_to};
use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;
use primus_ntt::NttTable;
use primus_poly::DcrtPolynomial;
use primus_reduce::FieldContext;
use rand::distr::Uniform;

use super::HybridRnsGlweKeySwitchingKey;
use crate::{
    CrtGlweEncryptionParameters, DcrtGlweSecretKey, GlweSecretKey, HybridRnsKeySwitchDomain,
};

impl<T: FheUint> HybridRnsGlweKeySwitchingKey<T> {
    /// Generates a hybrid-RNS key-switching key in the NTT domain over `QP`.
    /// The input sampling state supplies layout, ordered Q and key noise without
    /// a BFV codec; the noise support is also checked against the auxiliary P limbs.
    ///
    /// # Panics
    ///
    /// Panics if the input secret's dimension or polynomial length differs
    /// from `input_parameters`, if polynomial lengths or ordered Q moduli
    /// are incompatible, if key sizes overflow, or if the input noise
    /// magnitude bound is not strictly less than every QP modulus.
    /// These checks precede random sampling.
    ///
    /// # Correctness
    /// Both signed secrets' magnitudes must fit below every QP modulus,
    /// following [`DcrtGlweSecretKey::from_coeff_secret_key`]'s bounded-lift contract.
    pub fn generate<R, M, QpTable>(
        input_secret_key: &GlweSecretKey<T>,
        input_parameters: &CrtGlweEncryptionParameters<T>,
        output_secret_key: &GlweSecretKey<T>,
        domain: &HybridRnsKeySwitchDomain<'_, T, M, QpTable>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        QpTable: NttTable<ValueT = T>,
    {
        let input_size = input_parameters.size();
        let input_dimension = input_size.dimension();
        let poly_length = input_size.poly_length().get();
        let q_moduli_count = input_size.moduli_count();

        let hybrid_rns = domain.hybrid_rns();
        let qp_table = domain.table();

        // Validate the complete input layout before zip can truncate a key row
        // or its coefficients, and before consuming randomness.
        assert_eq!(
            input_secret_key.glwe_size(),
            input_size.glwe_size(),
            "hybrid input secret key layout mismatch"
        );
        input_parameters
            .validate_base(hybrid_rns.q_base())
            .expect("hybrid input parameters and Q basis are incompatible");
        assert_eq!(output_secret_key.poly_length().get(), poly_length);
        assert_eq!(qp_table.poly_length().get(), poly_length);

        let qp_moduli = hybrid_rns.qp_base().moduli();
        let noise_distribution = input_parameters.noise_distribution();
        assert!(
            qp_moduli.iter().all(|modulus| {
                let q: u128 = modulus.value().as_into();
                u128::from(noise_distribution.maximum_magnitude()) < q
            }),
            "noise magnitude bound must be less than every QP modulus"
        );
        let p_mod_q = hybrid_rns.p_mod_q();
        let partition_count = hybrid_rns.partition_count();
        let qp_moduli_values: Vec<T> = qp_moduli.iter().map(|modulus| modulus.value()).collect();
        let qp_uniform_distributions: Vec<Uniform<T>> = qp_moduli
            .iter()
            .map(|modulus| modulus.uniform_distribution())
            .collect();

        let output_secret_key_qp =
            DcrtGlweSecretKey::from_coeff_secret_key(output_secret_key, qp_table);
        let output_secret_key_qp = output_secret_key_qp.key();

        let output_size = RnsGlweSize::new(output_secret_key.glwe_size(), q_moduli_count);
        let qp_size = RnsGlweSize::new(output_secret_key.glwe_size(), hybrid_rns.qp_moduli_count());
        let qp_gadget_len = partition_count
            .checked_mul(qp_size.rns_glwe_len())
            .expect("hybrid QP gadget length overflow");
        let key_len = input_dimension
            .get()
            .checked_mul(qp_gadget_len)
            .expect("hybrid key-switching key length overflow");
        let mut key = vec![T::ZERO; key_len];

        for (secret_polynomial, key_for_secret) in input_secret_key
            .iter()
            .zip(key.chunks_exact_mut(qp_gadget_len))
        {
            for (partition, key_entry) in hybrid_rns
                .partitions()
                .zip(key_for_secret.chunks_exact_mut(qp_size.rns_glwe_len()))
            {
                let (mask, body) = key_entry.split_at_mut(qp_size.rns_mask_len());
                sample_crt_gaussian_values_to(
                    body,
                    poly_length,
                    &qp_moduli_values,
                    noise_distribution,
                    rng,
                );

                let q_range = partition.q_range();
                let partition_elements = q_range.start * poly_length..q_range.end * poly_length;
                for ((body_limb, modulus), &scalar) in body[partition_elements]
                    .chunks_exact_mut(poly_length)
                    .zip(&qp_moduli[q_range])
                    .zip(&p_mod_q[q_range])
                {
                    for (body_coefficient, &secret_coefficient) in
                        body_limb.iter_mut().zip(secret_polynomial)
                    {
                        let secret_residue = modulus.encode_signed(secret_coefficient);
                        *body_coefficient = modulus.reduce_add(
                            *body_coefficient,
                            modulus.reduce_mul(scalar, secret_residue),
                        );
                    }
                }

                qp_table.transform_slice(body);
                let mut body = DcrtPolynomial(body);
                for (mask_polynomial, output_secret_polynomial) in mask
                    .chunks_exact_mut(qp_size.rns_poly_len())
                    .zip(output_secret_key_qp.chunks_exact(qp_size.rns_poly_len()))
                {
                    sample_crt_uniform_values_to(
                        mask_polynomial,
                        poly_length,
                        &qp_uniform_distributions,
                        rng,
                    );
                    body.add_mul_assign(
                        &DcrtPolynomial(mask_polynomial),
                        &DcrtPolynomial(output_secret_polynomial),
                        poly_length,
                        qp_moduli,
                    );
                }
            }
        }

        Self {
            key,
            input_size,
            output_size,
            qp_size,
            partition_moduli_count: hybrid_rns.partition_moduli_count(),
            qp_moduli: qp_moduli_values,
            qp_gadget_len,
        }
    }
}
