//! Full and compact selectors, dual output, and paired bootstrap.

use primus_integer::FheUint;
use primus_lattice::nlev::Nlev;
use primus_ntru::NttNtruExternalProductWorkspace;
use primus_ntt::MonomialNttTable;
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, CircuitBootstrapServerKey, Lwe, LweCiphertext, OneHotEvaluator,
};

use super::{Context, PhaseOracle, RingSelection, lift_probe};

/// Check full and compact selection before the pair plus single-tail comparison.
pub(super) fn check_selectors<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    context: &Context<T, Table>,
    server: &CircuitBootstrapServerKey<T>,
    ring: &mut RingSelection<'_, T, Table>,
    phase: &mut PhaseOracle<'_, T, Table>,
    mut input: LweCiphertext<T>,
    mut encrypt: impl FnMut(usize, &mut LweCiphertext<T>),
) -> (Vec<T>, Vec<T>) {
    let mut one_hot = context.one_hot_evaluator(server).unwrap();
    let mut selectors = one_hot.allocate_nonzero_ngsw_output();
    let mut full = one_hot.allocate_ngsw_output();
    let mut ordinary_outputs = None;
    for m in [0, 3, 1, 2] {
        encrypt(m, &mut input);
        one_hot.one_hot_nonzero_ngsw_to(input.as_view(), &mut selectors);
        if m == 0 || m == 3 {
            // Full output adds delta_0. Check its true and false values and the
            // identical compact rows on both inputs.
            one_hot.one_hot_ngsw_to(input.as_view(), &mut full);
            assert_eq!(&full[one_hot.ngsw_selector_len()..], selectors);
            let zero = one_hot.ngsw_selectors(&full).selector(0).unwrap();
            one_hot.cmux_to(
                zero,
                ring.candidates[0].as_view(),
                ring.candidates[1].as_view(),
                ring.selected.as_mut_view(),
            );
            ring.client.decrypt_to(&ring.selected, &mut ring.decoded);
            assert_eq!(ring.decoded, ring.messages[usize::from(m == 0)]);
        }
        one_hot.cmux_k_to(
            one_hot.nonzero_ngsw_selectors(&selectors),
            ring.candidates[0].as_view(),
            &ring.candidates[1..],
            ring.selected.as_mut_view(),
        );
        ring.client.decrypt_to(&ring.selected, &mut ring.decoded);
        assert_eq!(ring.decoded, ring.messages[m], "one-hot input {m}");
        if m == 3 {
            ordinary_outputs = Some(check_dual_output(
                context,
                &mut one_hot,
                input.as_view(),
                ring,
                phase,
                &mut selectors,
                &mut full,
            ));
        }
    }

    let mut inputs = [input.clone(), input.clone(), input];
    for (message, input) in [0, 3, 1].into_iter().zip(&mut inputs) {
        encrypt(message, input);
    }
    assert_pair_matches_single(
        one_hot,
        inputs.each_ref().map(|input| input.as_view()),
        context.parameters().blind_rotation_method() != BlindRotationMethod::Classic,
    );
    ordinary_outputs.unwrap()
}

/// Dual output retains ordinary trace/SS for every projection strategy.
/// Consume NLEV as a public lift and compact NGSW in an encrypted selection.
fn check_dual_output<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    context: &Context<T, Table>,
    one_hot: &mut OneHotEvaluator<'_, T, Table>,
    input: Lwe<&[T]>,
    ring: &mut RingSelection<'_, T, Table>,
    phase: &mut PhaseOracle<'_, T, Table>,
    selectors: &mut [T],
    full: &mut [T],
) -> (Vec<T>, Vec<T>) {
    let mut nlev = one_hot.allocate_nlev_output();
    let mut standalone = one_hot.allocate_nlev_output();
    one_hot.one_hot_nlev_to(input.as_view(), &mut standalone);
    one_hot.one_hot_nlev_and_nonzero_ngsw_to(input.as_view(), &mut nlev, selectors);
    assert_eq!(nlev, standalone);
    one_hot.one_hot_to(input.as_view(), &mut nlev, full);
    assert_eq!(nlev, standalone);
    assert_eq!(&full[one_hot.ngsw_selector_len()..], selectors);

    // Selector 3 is active on this input. The zero selector must lift zero.
    let n = context.parameters().poly_length();
    let basis = context.cbs_parameters().unwrap().gadget().output_basis();
    let scalar = basis.scalar_iter().next().unwrap();
    let polynomial = lift_probe(n.get(), scalar);
    let mut product = NttNtruExternalProductWorkspace::new(n);
    for selector in [0, 3] {
        let control = one_hot.nlev_selectors(&nlev).selector(selector).unwrap();
        let transformed_control =
            Nlev::new(control.as_ref().to_vec()).into_ntt_form(context.table());
        transformed_control.external_product_to(
            &polynomial,
            &mut ring.selected,
            basis,
            phase.modulus,
            context.table(),
            &mut product,
        );
        phase.assert_lift(&ring.selected, polynomial.as_ref(), selector == 3, scalar);
    }
    let ordinary_outputs = (nlev, full.to_vec());
    one_hot.cmux_k_to(
        one_hot.nonzero_ngsw_selectors(selectors),
        ring.candidates[0].as_view(),
        &ring.candidates[1..],
        ring.selected.as_mut_view(),
    );
    ring.client.decrypt_to(&ring.selected, &mut ring.decoded);
    assert_eq!(ring.decoded, ring.messages[3], "dual one-hot input 3");
    ordinary_outputs
}

/// Pair callbacks and odd single tails preserve projection strategy and dirty-buffer reuse.
fn assert_pair_matches_single<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
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
