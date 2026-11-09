//! Prepared public encryption, gadget encryption and explicit scratch erasure.
//!
//! Run: cargo run -p primus_glwe_rns --example public_encryption
//! The small ring demonstrates API composition, not secure parameters.

use primus_decompose::DecompositionBaseLog;
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    BfvRnsCodec, CrtGlevParameters, CrtGlweEncryptionParameters, CrtGlweParameters,
    DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace, DcrtGlweDomain,
    DcrtGlwePublicKey, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize, ggsw::DcrtGgsw};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_rns::{RNSBase, Residues};
use primus_shape::PolyLength;
use std::sync::Arc;
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let values = [1_125_899_906_826_241u64, 1_125_899_906_629_633];
    let moduli = values.map(BarrettModulus::new);
    let n = PolyLength::new(32);
    let base = RNSBase::new(&moduli)?;
    let table = U64DcrtTable::new(n, &moduli)?;
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), n), values.len());
    let sampling = Arc::new(CrtGlweEncryptionParameters::try_with_error_distribution(
        size,
        &base,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 21 },
    )?);
    let mut rng = rand::rng();
    let coefficient_key =
        GlweSecretKey::generate(size.glwe_size(), sampling.secret_key_sampler(), &mut rng);
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
    let public = DcrtGlwePublicKey::new(&key, &sampling, &base, &table, &mut rng);

    // Raw mode encrypts the caller's encoded CRT phase directly, without t/gamma.
    let raw_domain = DcrtGlweDomain::try_new(&sampling, &base, &table)?;
    let mut raw = public.try_bind_raw(&raw_domain)?;
    let mut output = DcrtGlweCiphertext::<Vec<u64>>::zero(size.rns_glwe_len());
    let message = CrtPolynomial::new(vec![3u64; size.rns_poly_len()]);
    raw.encrypt_encoded_crt_to(&message, &mut output, &mut rng);
    raw.encrypt_zeros_to(&mut output, &mut rng);
    raw.workspace_mut().zeroize(); // Keeps the allocation ready for reuse.

    // Ordinary BFV mode accepts unscaled CRT lifts and applies delta exactly once.
    let parameters = CrtGlweParameters::try_from_parts(
        Arc::clone(&sampling),
        BfvRnsCodec::new(BarrettModulus::new(17), base, BarrettModulus::new(65_537)),
    )?;
    let mut encryptor = public.try_bind(&parameters, &table)?;
    let secret = key.try_bind(&parameters, &table)?;
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(size);
    let mut decoded = Polynomial::<Vec<u64>>::zero(n.get());
    for value in [3u64, 5] {
        let message = CrtPolynomial::new(vec![value; size.rns_poly_len()]);
        encryptor.encrypt_plaintext_crt_to(&message, &mut output, &mut rng);
        secret.decrypt_to(&output, &mut decoded, &mut decrypt_workspace);
        assert!(
            decoded
                .as_ref()
                .iter()
                .all(|&coefficient| coefficient == value)
        );
    }
    encryptor.workspace_mut().zeroize();

    let gadget =
        CrtGlevParameters::with_glwe_params(&parameters, DecompositionBaseLog::new(20), None);
    let gadget_domain = DcrtGadgetDomain::try_new(&gadget, &table)?;
    let mut gadget_encryptor = public.try_bind_gadget(&gadget_domain)?;
    let coefficients = Residues::new(vec![1u64; values.len()]);
    let mut gadget_output = DcrtGgsw::<Vec<u64>>::zero(gadget.rns_ggsw_len());
    gadget_encryptor.encrypt_monomial_ggsw_to(&coefficients, 7, &mut gadget_output, &mut rng);
    gadget_encryptor.encrypt_monomial_ggsw_to(&coefficients, 0, &mut gadget_output, &mut rng);
    gadget_encryptor.workspace_mut().zeroize();
    println!("prepared public encryption and gadget output reuse verified");
    Ok(())
}
