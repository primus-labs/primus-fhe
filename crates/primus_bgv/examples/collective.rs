//! Local two-owner arithmetic demonstration, not a distributed protocol or
//! parameter certificate. Native shares are consumed into online clients only
//! after key generation. Each owner keeps its own secret; no aggregate secret is built.
//! Run: cargo run -p primus_bgv --example collective
use primus_bgv::{
    BgvClient, BgvCollectivePublicKey, BgvCollectiveRelinearization, BgvContext, BgvModulusSwitch,
    BgvMultiplication, BgvParameters,
};
use primus_decompose::{DecompositionBaseLog, DecompositionConfig};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::{DcrtPolynomial, Polynomial};
use primus_reduce::{ReduceInv, ReduceMul};
use primus_shape::PolyLength;
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = BgvContext::try_with_levels(
        BgvParameters::try_with_error_distribution(
            PolyLength::new(32),
            BarrettModulus::new(193),
            &[1_125_899_905_351_681, 1_125_899_905_744_897].map(BarrettModulus::new),
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )?,
        2,
    )?;
    let mut rng = StdRng::seed_from_u64(15);
    let mut generate_share = || {
        let coefficient = GlweSecretKey::generate(
            context.parameters().size().glwe_size(),
            context
                .parameters()
                .encryption_parameters()
                .secret_key_sampler(),
            &mut rng,
        );
        DcrtGlweSecretKey::from_coeff_secret_key(&coefficient, context.table())
    };
    let alice = generate_share();
    let bob = generate_share();

    let public_setup = BgvCollectivePublicKey::try_new(&context, &mut rng)?;
    let mut public_sum = public_setup.aggregate();
    public_sum.add(&public_setup.contribute(&alice, &mut rng)?)?;
    public_sum.add(&public_setup.contribute(&bob, &mut rng)?)?;
    let public_key = public_setup.finalize(public_sum)?;

    let setup = BgvCollectiveRelinearization::try_new(
        &context,
        0,
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(5),
            level_count: None,
        },
        &mut rng,
    )?;
    let (alice_first, alice_state) = setup.start(&alice, &mut rng)?;
    let (bob_first, bob_state) = setup.start(&bob, &mut rng)?;
    let mut first_sum = setup.round_one_aggregate();
    first_sum.add(&alice_first)?;
    first_sum.add(&bob_first)?;
    let first = setup.freeze_round_one(first_sum)?;
    let mut second_sum = setup.round_two_aggregate(&first)?;
    second_sum.add(&alice_state.round2(&first, &mut rng)?)?;
    second_sum.add(&bob_state.round2(&first, &mut rng)?)?;
    let relinearization_key = setup.finalize(&first, second_sum)?;
    let alice = BgvClient::try_from_secret_key(&context, alice)?;
    let bob = BgvClient::try_from_secret_key(&context, bob)?;

    let mut message = context.new_plaintext();
    message.as_mut()[..2].copy_from_slice(&[3, 2]);
    let input = context
        .public_key_encryptor(&public_key)?
        .encrypt_centered(&message, &mut rng);
    let mut output = context.new_ciphertext(0);
    BgvMultiplication::try_new(&context, &relinearization_key)?.square_to(&input, &mut output);
    let mut dropped = context.new_ciphertext(1);
    BgvModulusSwitch::new(&context, 0).switch_to(&output, &mut dropped);

    // Arithmetic-only opening after dropping to one remaining data prime. A real
    // collective protocol additionally requires authenticated complete rosters,
    // fresh privacy flooding and one-use authorization before partial products.
    // Authenticate the correction factor with the same ciphertext/request;
    // bare partial products do not authenticate it or provide privacy.
    let len = context.rns_poly_len(1);
    let mut phase = DcrtPolynomial(dropped.as_ref()[..len].to_vec());
    let mut partial = DcrtPolynomial(vec![0; len]);
    alice.partial_phase_to(&dropped, 1, &mut partial)?;
    phase.add_assign(&partial, 32, context.base_q(1).moduli());
    bob.partial_phase_to(&dropped, 1, &mut partial)?;
    phase.add_assign(&partial, 32, context.base_q(1).moduli());
    context.table().ntt_tables()[0].inverse_transform_slice(phase.as_mut());
    let q = i128::from(context.base_q(1).moduli_values()[0]);
    let p = context.parameters().plain_modulus();
    let inverse_factor = p.reduce_inv(dropped.correction_factor());
    let decoded = Polynomial::new(
        phase
            .as_ref()
            .iter()
            .map(|&x| {
                let x = i128::from(x);
                let centered = if x > q / 2 { x - q } else { x };
                p.reduce_mul(centered.rem_euclid(193) as u64, inverse_factor)
            })
            .collect::<Vec<_>>(),
    );
    assert_eq!(&decoded.as_ref()[..3], &[9, 12, 4]);
    assert!(decoded.as_ref()[3..].iter().all(|&x| x == 0));
    println!(
        "collective (3+2X)^2 = 9+12X+4X² after prime drop, correction factor {}",
        dropped.correction_factor()
    );
    Ok(())
}
