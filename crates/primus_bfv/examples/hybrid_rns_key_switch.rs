//! BFV encryption, raw Hybrid-RNS key switching and BFV recovery.
//! Run: cargo run -p primus_bfv --example hybrid_rns_key_switch
//! These parameters demonstrate composition, not a security level.

use primus_bfv::{BfvCiphertext, BfvDecryptWorkspace, BfvParameters, BfvSecretKeyContext};
use primus_glwe_rns::{
    DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, HybridRnsGlweKeySwitchEvaluator,
    HybridRnsGlweKeySwitchingKey, SecretKeyDistr,
};
use primus_lattice::glwe::DcrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::U64DcrtTable;
use primus_poly::Polynomial;
use primus_rns::HybridRNS;
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    type Value = u64;

    let poly_length = PolyLength::new(512);
    let plaintext_modulus = BarrettModulus::new(12289);
    let gamma = BarrettModulus::new(2305843009213554689);
    let q_moduli = [1125899906826241, 1125899906629633, 1125899906031617].map(BarrettModulus::new);
    let p_moduli = [1125899905036289].map(BarrettModulus::new);
    let qp_moduli: Vec<_> = q_moduli.iter().chain(&p_moduli).copied().collect();
    let q_table = U64DcrtTable::new(poly_length, &q_moduli).unwrap();
    let qp_table = U64DcrtTable::new(poly_length, &qp_moduli).unwrap();

    let glwe_parameters = BfvParameters::new(
        poly_length,
        plaintext_modulus,
        gamma,
        &q_moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );
    let hybrid_rns = HybridRNS::new(&q_moduli, &p_moduli, 2).unwrap();

    // Client: generate both secrets and the switching key supplied to the server.
    let mut rng = StdRng::seed_from_u64(0x4859_4252_4944_524e);
    let input_key = GlweSecretKey::generate(
        glwe_parameters.size().glwe_size(),
        glwe_parameters.encryption_parameters().secret_key_sampler(),
        &mut rng,
    );
    let output_key = GlweSecretKey::generate(
        glwe_parameters.size().glwe_size(),
        glwe_parameters.encryption_parameters().secret_key_sampler(),
        &mut rng,
    );
    let input_dcrt_key = DcrtGlweSecretKey::from_coeff_secret_key(&input_key, &q_table);
    let output_dcrt_key = DcrtGlweSecretKey::from_coeff_secret_key(&output_key, &q_table);
    let switching_key = HybridRnsGlweKeySwitchingKey::generate(
        &input_key,
        glwe_parameters.encryption_parameters(),
        &output_key,
        &hybrid_rns,
        &qp_table,
        &mut rng,
    );

    let plaintext: Polynomial<Vec<Value>> =
        Polynomial::random(poly_length.get(), plaintext_modulus, &mut rng);
    let mut input: DcrtGlwe<Vec<Value>> =
        DcrtGlweCiphertext::zero(glwe_parameters.size().rns_glwe_len());
    let mut output: DcrtGlwe<Vec<Value>> =
        DcrtGlweCiphertext::zero(glwe_parameters.size().rns_glwe_len());
    let input_dcrt_key_context =
        BfvSecretKeyContext::try_new(&input_dcrt_key, &glwe_parameters, &q_table).unwrap();
    let mut native = BfvCiphertext::zero(glwe_parameters.size().rns_glwe_len());
    input_dcrt_key_context.encrypt_to(&plaintext, &mut native, &mut rng);
    // The raw switching key retains b-a*s. Cross this legacy boundary explicitly;
    // ordinary BFV encryption/decryption use native [c0,c1] throughout.
    native.write_raw_glwe_to(&mut input, &glwe_parameters);

    // Server: bind evaluation resources once, allocating reusable scratch.
    let mut key_switch_evaluator =
        HybridRnsGlweKeySwitchEvaluator::new(&switching_key, &hybrid_rns, &qp_table);
    key_switch_evaluator.key_switch_to(&input, &mut output);

    // Client: decrypt under the output secret using its bound parameters and table.
    let mut decrypt_workspace = BfvDecryptWorkspace::new(&glwe_parameters);
    let output_dcrt_key_context =
        BfvSecretKeyContext::try_new(&output_dcrt_key, &glwe_parameters, &q_table).unwrap();
    native.set_from_raw_glwe(&output, &glwe_parameters);
    let decrypted = output_dcrt_key_context.decrypt(&native, &mut decrypt_workspace);
    assert_eq!(decrypted, plaintext);
}
