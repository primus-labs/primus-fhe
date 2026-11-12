//! CBS row phases, selector consumption and return to LWE.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::phase_error_magnitude;
use primus_integer::FheUint;
use primus_lattice::ntru::{Ntru, NttNtru};
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::{
    BlockOccupancy, NtruSecretKey, NttNgswCiphertext, NttNlevCiphertext,
    NttNtruExternalProductWorkspace, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_reduce::{EncodeSigned, ReduceMul};
use primus_tfhe::DecompositionLevelCount;
use primus_tfhe_ntru_ntt::{
    AccumulatorClient, BlindRotationMethod, CbsConfig, CbsEvaluator, CircuitBootstrapServerKey,
    ClientKey, KeyGenerator, LweCiphertext, NtruProjectionMethod, PbsConfig, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    fixture::{cbs_gadget, config},
    pbs::many_lut_and_mvb,
};

mod binding;
mod one_hot;

use self::binding::{assert_msb_lookup_is_rejected, check_resources_and_return};

type Context<T, Table> = TfheContext<T, Table, PowOf2Modulus<T>>;

/// Consume predicate and one-hot controls with the same test key, then return
/// the ordinary projection outputs for a fixed-seed cross-strategy comparison.
pub(super) fn circuit_selection<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    pbs: PbsConfig<T, PowOf2Modulus<T>>,
    projection: NtruProjectionMethod,
) -> (Vec<T>, Vec<T>) {
    let context = Context::<T, Table>::try_from_cbs_config(CbsConfig {
        pbs,
        projection,
        fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        gadget: cbs_gadget(Some(DecompositionLevelCount::new(3))),
    })
    .unwrap();
    // The independent input RNG keeps ciphertexts stable across projection strategies.
    let seed = if pbs.method == BlindRotationMethod::Block {
        if T::BITS == 32 { 100 } else { 106 }
    } else {
        103
    };
    let mut rng = StdRng::seed_from_u64(seed);
    let mut input_rng = StdRng::seed_from_u64(104);
    let (client, server, public_lift) = if pbs.method == BlindRotationMethod::Block && T::BITS == 64
    {
        KeyGenerator::new(&context)
            .try_generate_circuit_bootstrap_keys_with_public_lift(
                Some(context.parameters().blind_rotation()),
                &mut rng,
            )
            .unwrap()
    } else {
        let (client, server) = context
            .try_generate_circuit_bootstrap_keys(&mut rng)
            .unwrap();
        (client, server, None)
    };
    if let SecretKeyDistr::BlockBinary {
        block_size,
        occupancy: BlockOccupancy::AtMostOne,
    } = pbs.external_lwe.secret_key_distr
    {
        assert!(
            client.external_lwe_secret_key().as_ref()[..block_size]
                .iter()
                .all(|&s| s == T::ZERO)
        );
    }

    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut encrypt = |message: usize, input: &mut LweCiphertext<T>| {
        encryptor
            .encrypt_padded_to(T::as_from(message), input.as_mut_view(), &mut input_rng)
            .unwrap();
    };
    let mut ring = RingSelection::new(&context, &client, &mut rng);
    let mut input = context.allocate_lwe_ciphertext();
    let program = context
        .compile_cbs_fn(|m| T::as_from(usize::from(m >= 2)))
        .unwrap();
    let mut cbs = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
        .unwrap();
    let mut control = cbs.allocate_output();

    assert_msb_lookup_is_rejected(&context, &server);
    let mut phase = PhaseOracle::new(&context, client.accumulator_ntru_secret_key());
    if let Some(lift) = public_lift {
        check_public_lift(&context, &server, &lift, &mut ring, &mut phase);
    }
    check_predicate(
        &mut cbs,
        &mut control,
        &mut ring,
        &mut phase,
        context.cbs_parameters().unwrap().gadget().output_basis(),
        &mut input,
        &mut encrypt,
    );
    check_resources_and_return(
        &context,
        &client,
        &server,
        cbs,
        &mut control,
        input.as_view(),
        &ring,
    );
    one_hot::check_selectors(&context, &server, &mut ring, &mut phase, input, encrypt)
}

/// The encrypted candidates and scratch reused by predicate and selector tests.
struct RingSelection<'a, T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    client: AccumulatorClient<'a, T, Table, PowOf2Modulus<T>>,
    messages: [Vec<T>; 4],
    candidates: [Ntru<Vec<T>>; 4],
    selected: Ntru<Vec<T>>,
    decoded: Vec<T>,
}

impl<'a, T: FheUint, Table: MonomialNttTable<ValueT = T>> RingSelection<'a, T, Table> {
    fn new(context: &'a Context<T, Table>, client: &ClientKey<T>, rng: &mut StdRng) -> Self {
        let mut client = context
            .accumulator_client(client.accumulator_ntru_secret_key(), T::as_from(8))
            .unwrap();
        let n = context.parameters().poly_length().get();
        // A short periodic pattern could hide an incorrect coefficient rotation.
        let messages: [Vec<T>; 4] = std::array::from_fn(|r| {
            (0..n)
                .map(|i| T::as_from(((i >> r) + i / 7 + r) % 4))
                .collect()
        });
        let candidates = messages
            .each_ref()
            .map(|message| client.encrypt(message, rng));
        Self {
            client,
            messages,
            candidates,
            selected: context.allocate_accumulator_ciphertext(),
            decoded: vec![T::ZERO; n],
        }
    }
}

/// Reuses decryption scratch to check full coefficient phases independently of
/// the accumulator client's message decoder.
struct PhaseOracle<'a, T: FheUint, Table: MonomialNttTable<ValueT = T>> {
    table: &'a Table,
    modulus: BarrettModulus<T>,
    secret: &'a NtruSecretKey<T>,
    transformed_secret: NttNtruSecretKey<T>,
    transformed_input: NttNtru<Vec<T>>,
    phase: Polynomial<Vec<T>>,
}

impl<'a, T: FheUint, Table: MonomialNttTable<ValueT = T>> PhaseOracle<'a, T, Table> {
    fn new(context: &'a Context<T, Table>, secret: &'a NtruSecretKey<T>) -> Self {
        let table = context.table();
        let modulus = context.parameters().accumulator_ntru().cipher_modulus();
        let n = context.parameters().poly_length().get();
        Self {
            table,
            modulus,
            secret,
            transformed_secret: NttNtruSecretKey::try_from_coeff_secret_key(secret, modulus, table)
                .unwrap(),
            transformed_input: NttNtru::new(vec![T::ZERO; n]),
            phase: Polynomial::new(vec![T::ZERO; n]),
        }
    }

    fn decrypt_coeff(&mut self, input: &Ntru<Vec<T>>) {
        input.write_ntt_form(&mut self.transformed_input, self.table);
        self.transformed_secret.decrypt_phase_to(
            &self.transformed_input,
            &mut self.phase,
            self.modulus,
            self.table,
        );
    }

    /// NGSW encrypts bit*g_l*f at every secret coefficient. The scalar/16 bound
    /// is a regression tolerance for these small, fixed parameters.
    fn assert_ngsw(&self, bit: T, scalar: T) {
        let weight = self.modulus.reduce_mul(bit, scalar);
        for (&actual, &coefficient) in self.phase.as_ref().iter().zip(self.secret.as_slice()) {
            let expected = self
                .modulus
                .reduce_mul(weight, self.modulus.encode_signed(coefficient));
            assert!(
                phase_error_magnitude(actual, expected, self.modulus) <= scalar >> 4u32,
                "actual {actual:?}, expected {expected:?}, scalar {scalar:?}"
            );
        }
    }

    /// A public NLEV lift encrypts the selected polynomial or zero.
    fn assert_lift(&mut self, output: &Ntru<Vec<T>>, polynomial: &[T], active: bool, scalar: T) {
        self.decrypt_coeff(output);
        for (&actual, &value) in self.phase.as_ref().iter().zip(polynomial) {
            let expected = if active { value } else { T::ZERO };
            assert!(phase_error_magnitude(actual, expected, self.modulus) <= scalar >> 4u32);
        }
    }
}

fn lift_probe<T: FheUint>(n: usize, scalar: T) -> Polynomial<Vec<T>> {
    Polynomial::new(
        (0..n)
            .map(|i| if i % 3 == 0 { scalar } else { T::ZERO })
            .collect(),
    )
}

/// An empty first Block must use an independent encryption of one for public lift.
fn check_public_lift<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    context: &Context<T, Table>,
    server: &CircuitBootstrapServerKey<T>,
    lift: &NttNlevCiphertext<Vec<T>>,
    ring: &mut RingSelection<'_, T, Table>,
    phase: &mut PhaseOracle<'_, T, Table>,
) {
    assert!(
        server
            .server_key()
            .blind_rotation_key()
            .classic_controls()
            .is_none()
    );
    let n = context.parameters().poly_length();
    let basis = context.cbs_parameters().unwrap().gadget().output_basis();
    let scalar = basis.scalar_iter().next().unwrap();
    let polynomial = lift_probe(n.get(), scalar);
    let mut product = NttNtruExternalProductWorkspace::new(n);
    lift.external_product_to(
        &polynomial,
        &mut ring.selected,
        context.parameters().blind_rotation().basis(),
        phase.modulus,
        context.table(),
        &mut product,
    );
    phase.assert_lift(&ring.selected, polynomial.as_ref(), true, scalar);
}

/// Check both predicate values, every gadget level, and encrypted CMux consumption.
fn check_predicate<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    cbs: &mut CbsEvaluator<'_, T, Table>,
    control: &mut NttNgswCiphertext<Vec<T>>,
    ring: &mut RingSelection<'_, T, Table>,
    phase: &mut PhaseOracle<'_, T, Table>,
    basis: &ApproxSignedBasis<T>,
    input: &mut LweCiphertext<T>,
    mut encrypt: impl FnMut(usize, &mut LweCiphertext<T>),
) {
    let n = phase.table.poly_length().get();
    let mut probe = Ntru::new(vec![T::ZERO; n]);
    for m in [0, 2] {
        encrypt(m, input);
        cbs.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        let bit = T::as_from(usize::from(m >= 2));
        for (row, scalar) in control.iter_ntt_ntru(n).zip(basis.scalar_iter()) {
            phase.transformed_secret.decrypt_phase_to(
                &row,
                &mut phase.phase,
                phase.modulus,
                phase.table,
            );
            phase.assert_ngsw(bit, scalar);
            // A lone gadget weight exercises this output level even when an
            // ordinary t8 CMux cannot detect a missing low level.
            probe.as_mut().fill(T::ZERO);
            probe.as_mut()[0] = scalar;
            cbs.external_product_to(
                control.as_view(),
                probe.as_view(),
                ring.selected.as_mut_view(),
            );
            phase.decrypt_coeff(&ring.selected);
            phase.assert_ngsw(bit, scalar);
        }
        cbs.cmux_to(
            control.as_view(),
            ring.candidates[0].as_view(),
            ring.candidates[1].as_view(),
            ring.selected.as_mut_view(),
        );
        assert_eq!(
            ring.client.decrypt(&ring.selected),
            ring.messages[usize::from(m >= 2)],
            "CBS input {m}"
        );
    }
}

#[test]
fn u32_fixed_weight_classic_batches_and_cbs() {
    let config = config(BlindRotationMethod::Classic);
    many_lut_and_mvb::<u32, U32NttTable>(config);
    circuit_selection::<u32, U32NttTable>(config, NtruProjectionMethod::PairedTrace);
}

#[test]
fn u64_classic_cbs() {
    let mut config = config(BlindRotationMethod::Classic);
    config.external_lwe.secret_key_distr = SecretKeyDistr::UniformTernary;
    use NtruProjectionMethod::*;
    let baseline = circuit_selection::<u64, U64NttTable>(config, Separate);
    for projection in [FusedLastStage, FusedLastThreeStages, PairedTrace] {
        let ordinary = circuit_selection::<u64, U64NttTable>(config, projection);
        // Fixed input/BR/trace/SS material: NLEV and dual NGSW must be identical,
        // independently of the selected NGSW-only algorithm and later KS sampling.
        assert_eq!(ordinary, baseline, "{projection:?}");
    }
}
