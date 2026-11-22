use primus_encoding::phase_error_magnitude;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::nlev::FourierNlev;
use primus_lwe::LweCiphertext;
use primus_modulus::PowOf2Modulus;
use primus_ntru::FourierNtruExternalProductWorkspace;
use primus_poly::Polynomial;
use primus_tfhe_ntru_fourier::{
    BlindRotationMethod, CircuitBootstrapServerKey, ClientKey, Lwe, OneHotEvaluator, TfheContext,
    circuit_bootstrap::CbsGadgetParameters,
};
use rand::rngs::StdRng;

use super::fixture::{PhaseDecryptor, RingSelection};

/// Compact selectors drive four-way CMux, including the default branch.
/// The same input stream then exercises paired projection and its single tail.
pub(super) fn check_one_hot_selection<T: TorusFftValue, Table: FftTable>(
    context: &TfheContext<T, Table, PowOf2Modulus<T>>,
    client: &ClientKey<T>,
    server: &CircuitBootstrapServerKey<T>,
    mut input: LweCiphertext<T>,
    ring: &mut RingSelection<'_, T, Table>,
    oracle: &mut PhaseDecryptor<'_, T, Table>,
    rng: &mut StdRng,
) {
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let gadget = context.cbs_parameters().unwrap().gadget();
    let is_block = context.parameters().blind_rotation_method() == BlindRotationMethod::Block;
    let mut one_hot = context.one_hot_evaluator(server).unwrap();
    let mut selectors = one_hot.allocate_nonzero_ngsw_output();
    for m in [0, 3, 1, 2] {
        encryptor
            .encrypt_padded_to(T::as_from(m), input.as_mut_view(), rng)
            .unwrap();
        one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
        one_hot.cmux_k_to(
            one_hot.nonzero_ngsw_selectors(&selectors),
            ring.candidates[0].as_view(),
            &ring.candidates[1..],
            ring.selected.as_mut_view(),
        );
        ring.client.decrypt_to(&ring.selected, &mut ring.decoded);
        assert_eq!(ring.decoded, ring.messages[m], "one-hot input {m}");
        if is_block && m == 3 {
            check_dual_selection(
                &mut one_hot,
                input.as_view(),
                &mut selectors,
                m,
                gadget,
                ring,
                oracle,
            );
        }
    }

    let mut inputs = [input.clone(), input.clone(), input];
    for (message, input) in [0, 3, 1].into_iter().zip(&mut inputs) {
        encryptor
            .encrypt_padded_to(T::as_from(message), input.as_mut_view(), rng)
            .unwrap();
    }
    assert_pair_matches_single(
        one_hot,
        inputs.each_ref().map(|input| input.as_view()),
        is_block,
    );
}

/// Both dual entry points retain the same NLEV controls. Consume those
/// controls for a public lift, then use the dual NGSW output with dirty scratch.
fn check_dual_selection<T: TorusFftValue, Table: FftTable>(
    one_hot: &mut OneHotEvaluator<'_, T, Table>,
    input: Lwe<&[T]>,
    selectors: &mut [Complex64],
    m: usize,
    gadget: &CbsGadgetParameters<T>,
    ring: &mut RingSelection<'_, T, Table>,
    oracle: &mut PhaseDecryptor<'_, T, Table>,
) {
    let basis = gadget.output_basis();
    let poly_length = gadget.poly_length();
    let n = poly_length.get();
    let modulus = primus_modulus::NativeModulus::new();
    let mut standalone = one_hot.allocate_nlev_output();
    let mut nlev = one_hot.allocate_nlev_output();
    let mut full = one_hot.allocate_ngsw_output();
    one_hot.one_hot_nlev_to(input.as_view(), &mut standalone);
    one_hot.one_hot_nlev_and_nonzero_ngsw_to(input.as_view(), &mut nlev, selectors);
    assert_eq!(nlev, standalone);
    one_hot.one_hot_to(input, &mut nlev, &mut full);
    assert_eq!(nlev, standalone);
    assert_eq!(&full[one_hot.ngsw_selector_len()..], selectors);
    let scalar = basis.scalar_iter().next().unwrap();
    let polynomial = Polynomial::new(
        (0..n)
            .map(|i| if i % 3 == 0 { scalar } else { T::ZERO })
            .collect::<Vec<_>>(),
    );
    let mut product = FourierNtruExternalProductWorkspace::new(poly_length);
    let mut transformed_control = FourierNlev::new(vec![
        Complex64::default();
        basis.level_count().get() * n / 2
    ]);
    for selector in [0, m] {
        let control = one_hot.nlev_selectors(&nlev).selector(selector).unwrap();
        control.write_fourier_form(&mut transformed_control, &mut oracle.fft);
        transformed_control.external_product_to(
            &polynomial,
            &mut ring.selected,
            basis,
            &mut oracle.fft,
            &mut product,
        );
        for (&actual, &value) in oracle
            .coefficient_phase(&ring.selected)
            .iter()
            .zip(polynomial.as_ref())
        {
            let expected = if selector == m { value } else { T::ZERO };
            assert!(phase_error_magnitude(actual, expected, modulus) <= scalar >> 4u32);
        }
    }
    one_hot.cmux_k_to(
        one_hot.nonzero_ngsw_selectors(selectors),
        ring.candidates[0].as_view(),
        &ring.candidates[1..],
        ring.selected.as_mut_view(),
    );
    ring.client.decrypt_to(&ring.selected, &mut ring.decoded);
    assert_eq!(ring.decoded, ring.messages[m], "dual one-hot input {m}");
}

/// Pair callbacks and odd single tails preserve projection strategy and dirty-buffer reuse.
pub(super) fn assert_pair_matches_single<T: TorusFftValue, Table: FftTable>(
    one_hot: OneHotEvaluator<'_, T, Table>,
    inputs: [Lwe<&[T]>; 3],
    has_pair: bool,
) {
    let (mut operation, mut resources) = one_hot.into_parts();
    let pair = operation.new_pair_workspace(&resources);
    assert_eq!(pair.is_some(), has_pair);
    let Some(mut pair) = pair else { return };
    let mut nlev = operation.allocate_nlev_output();
    let mut ngsw = operation.allocate_nonzero_ngsw_output();
    let mut expected_nlev = [nlev.clone(), nlev.clone(), nlev.clone()];
    let mut expected_ngsw = [ngsw.clone(), ngsw.clone(), ngsw.clone()];
    // An unwinding consumer must not leave the borrowed accumulator swapped out.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        operation.with_pair(
            [inputs[0].as_view(), inputs[1].as_view()],
            &mut pair,
            &mut resources,
            |_, projection| {
                projection.project_to(None, Some(ngsw.as_mut_slice()));
                panic!("intentional projection consumer failure");
            },
        );
    }));
    assert!(result.is_err());
    for (with_nlev, with_ngsw) in [(false, true), (true, false), (true, true)] {
        for (i, input) in inputs.iter().enumerate() {
            match (with_nlev, with_ngsw) {
                (true, true) => operation.one_hot_nlev_and_nonzero_ngsw_to(
                    input.as_view(),
                    &mut expected_nlev[i],
                    &mut expected_ngsw[i],
                    &mut resources,
                ),
                (true, false) => operation.one_hot_nlev_to(
                    input.as_view(),
                    &mut expected_nlev[i],
                    &mut resources,
                ),
                _ => operation.one_hot_nonzero_ngsw_to(
                    input.as_view(),
                    &mut expected_ngsw[i],
                    &mut resources,
                ),
            }
        }
        let mut visited = 0;
        operation.with_pair(
            [inputs[0].as_view(), inputs[1].as_view()],
            &mut pair,
            &mut resources,
            |i, projection| {
                assert_eq!(i, visited);
                visited += 1;
                projection.project_to(
                    with_nlev.then_some(nlev.as_mut_slice()),
                    with_ngsw.then_some(ngsw.as_mut_slice()),
                );
                if with_nlev {
                    assert_eq!(nlev, expected_nlev[i]);
                }
                if with_ngsw {
                    assert_eq!(ngsw, expected_ngsw[i]);
                }
            },
        );
        assert_eq!(visited, 2);
        for (i, input) in inputs.iter().enumerate().skip(2) {
            match (with_nlev, with_ngsw) {
                (true, true) => operation.one_hot_nlev_and_nonzero_ngsw_to(
                    input.as_view(),
                    &mut nlev,
                    &mut ngsw,
                    &mut resources,
                ),
                (true, false) => {
                    operation.one_hot_nlev_to(input.as_view(), &mut nlev, &mut resources)
                }
                _ => operation.one_hot_nonzero_ngsw_to(input.as_view(), &mut ngsw, &mut resources),
            }
            if with_nlev {
                assert_eq!(nlev, expected_nlev[i]);
            }
            if with_ngsw {
                assert_eq!(ngsw, expected_ngsw[i]);
            }
        }
    }
}
