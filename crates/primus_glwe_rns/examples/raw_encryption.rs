//! Codec-free coefficient phase encryption and full/partial phase extraction.
//!
//! Run: cargo run -p primus_glwe_rns --example raw_encryption
//! These small parameters demonstrate the API, not a secure parameter set.

use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    CrtGlweEncryptionParameters, DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey,
    SecretKeyDistr,
};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize};
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_rns::RNSBase;
use primus_shape::PolyLength;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let values = [1_125_899_906_826_241u64, 1_125_899_906_629_633];
    let moduli = values.map(BarrettModulus::new);
    let n = PolyLength::new(32);
    let base = RNSBase::new(&moduli)?;
    let table = U64DcrtTable::new(n, &moduli)?;
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), n), values.len());
    let parameters = CrtGlweEncryptionParameters::try_with_error_distribution(
        size,
        &base,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 21 },
    )?;
    let mut rng = rand::rng();
    let coefficient_key =
        GlweSecretKey::generate(size.glwe_size(), parameters.secret_key_sampler(), &mut rng);
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
    let context = key.try_bind_raw(&parameters, &base, &table)?;

    // This is already the intended CRT phase lift; no plaintext modulus, gamma
    // or BFV delta is used. Negative values have a separate residue in each limb.
    let message: Vec<i64> = (0..n.get()).map(|i| i as i64 % 7 - 3).collect();
    let encoded = CrtPolynomial::new(
        values
            .iter()
            .flat_map(|&q| {
                message
                    .iter()
                    .map(move |&value| i128::from(value).rem_euclid(i128::from(q)) as u64)
            })
            .collect::<Vec<_>>(),
    );
    let mut ciphertext = DcrtGlweCiphertext::<Vec<u64>>::zero(size.rns_glwe_len());
    context.encrypt_encoded_crt_to(&encoded, &mut ciphertext, &mut rng);

    let mut phase = DcrtPolynomial::<Vec<u64>>::zero(size.rns_poly_len());
    let mut partial = DcrtPolynomial::<Vec<u64>>::zero(size.rns_poly_len());
    key.phase_to(&ciphertext, &mut phase, &moduli); // b - a*s, still in NTT form.
    key.partial_phase_to(&ciphertext, &mut partial, &moduli); // -a*s, without b.
    let (_, body) = ciphertext.a_b(size.rns_poly_len());
    for (limb, &q) in values.iter().enumerate() {
        for i in 0..n.get() {
            let at = limb * n.get() + i;
            assert_eq!(
                phase.as_ref()[at],
                (body.as_ref()[at] + partial.as_ref()[at]) % q
            );
        }
    }
    // A protocol sums partial shares and adds b exactly once. Raw phase shares
    // alone provide neither opening privacy nor a one-use/retry policy.
    table.inverse_transform_slice(phase.as_mut());
    for (limb, &q) in values.iter().enumerate() {
        for i in 0..n.get() {
            let residual =
                (phase.as_ref()[limb * n.get() + i] + q - encoded.as_ref()[limb * n.get() + i]) % q;
            let centered = i128::from(residual) - if residual > q / 2 { i128::from(q) } else { 0 };
            assert!(centered.abs() <= 21);
        }
    }
    context.encrypt_zeros_to(&mut ciphertext, &mut rng); // Reuses the same output.
    println!("raw CRT phase encryption and additive phase relation verified");
    Ok(())
}
