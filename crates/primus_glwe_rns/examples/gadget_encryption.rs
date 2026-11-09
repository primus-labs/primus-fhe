//! Advanced public GGSW encryption with explicit gadget parameters and scratch.
//!
//! Run: cargo run -p primus_glwe_rns --example gadget_encryption
//! Start with public_encryption for raw phase encryption without a gadget basis.
//! The small ring demonstrates API composition, not secure parameters.

use primus_decompose::DecompositionBaseLog;
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweEncryptionParameters, DcrtGlweSecretKey, GlweSecretKey,
    SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize, ggsw::DcrtGgsw};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_rns::{RNSBase, Residues};
use primus_shape::PolyLength;
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let values = [1_125_899_906_826_241u64, 1_125_899_906_629_633];
    let moduli = values.map(BarrettModulus::new);
    let n = PolyLength::new(32);
    let base = RNSBase::new(&moduli)?;
    let table = U64DcrtTable::new(n, &moduli)?;
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), n), values.len());
    let sampling = CrtGlweEncryptionParameters::try_with_error_distribution(
        size,
        &base,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 21 },
    )?;
    let mut rng = rand::rng();
    let coefficient_key =
        GlweSecretKey::generate(size.glwe_size(), sampling.secret_key_sampler(), &mut rng);
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
    let public = key
        .try_bind_raw(&sampling, &base, &table)?
        .public_key(&mut rng);

    // Gadget arithmetic owns the base/decomposition. Sampling stays separate
    // so a distinct key role can select its required error distribution.
    let gadget = CrtGlevParameters::try_new(size, base, DecompositionBaseLog::new(20), None)?;
    let mut encryptor = public.try_bind_gadget(&gadget, &sampling, &table)?;
    let coefficients = Residues::new(vec![1u64; values.len()]);
    let mut output = DcrtGgsw::<Vec<u64>>::zero(gadget.rns_ggsw_len());
    for degree in [7, 0] {
        encryptor.encrypt_monomial_ggsw_to(&coefficients, degree, &mut output, &mut rng);
    }
    encryptor.workspace_mut().zeroize(); // Retains allocation and geometry.
    println!("prepared public GGSW encryption reused its output and scratch");
    Ok(())
}
