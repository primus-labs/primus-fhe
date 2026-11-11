//! Multi-way CMux shape boundaries and recovery after a streamed-pair failure.
//! Real encrypted selectors and numerical differentials live in primus_ntru.

use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable};
use primus_lattice::{
    ngsw::{FourierNgsw, FourierNgswOwned, NttNgsw},
    ntru::Ntru,
    workspace::{FourierNtruExternalProductWorkspace, NttNtruExternalProductWorkspace},
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::{N, POLY_LENGTH, unit_ngsw};

// The backend adapter maps each requested length to a view of the same control.
// This checks the shared public contract without duplicating encryption fixtures.
fn check_shapes(
    control_len: usize,
    mut cmux: impl FnMut(&[usize], Ntru<&[u32]>, &[Ntru<&[u32]>], Ntru<&mut [u32]>),
) {
    let default = Ntru::new([1; N]);
    let candidates = [Ntru::new(&[3; N][..]), Ntru::new(&[5; N][..])];
    let late_short_candidate = [candidates[0].as_view(), Ntru::new(&[5; N - 1][..])];
    let valid = [control_len; 2];
    let mut output = Ntru::new([9; N]);

    // Batch counts and fixed-buffer sizes fail before any output writes. A bad
    // first pair also leaves output untouched because both members are checked
    // before preparing its difference. Later errors may leave a partial result.
    for (controls, default_view, candidate_views, output_len, unchanged) in [
        (&valid[..], default.as_view(), &candidates[..1], N, true),
        (&valid[..1], default.as_view(), &candidates[..], N, true),
        (
            &valid[..],
            Ntru::new(&[1; N - 1][..]),
            &candidates[..],
            N,
            true,
        ),
        (&valid[..], default.as_view(), &candidates[..], N - 1, true),
        (
            &[control_len - 1][..],
            default.as_view(),
            &candidates[..1],
            N,
            true,
        ),
        (
            &[control_len + 1][..],
            default.as_view(),
            &candidates[..1],
            N,
            true,
        ),
        (
            &valid[..1],
            default.as_view(),
            &late_short_candidate[1..],
            N,
            true,
        ),
        (
            &[control_len, control_len - 1][..],
            default.as_view(),
            &candidates[..],
            N,
            false,
        ),
        (
            &valid[..],
            default.as_view(),
            &late_short_candidate[..],
            N,
            false,
        ),
    ] {
        output.as_mut().fill(9);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                cmux(
                    controls,
                    default_view,
                    candidate_views,
                    Ntru::new(&mut output.as_mut()[..output_len]),
                );
            }))
            .is_err()
        );
        if unchanged {
            assert_eq!(output.as_ref(), &[9; N]);
        }

        // A valid call overwrites any partial sum/difference left by the failure.
        cmux(
            &valid[..1],
            default.as_view(),
            &candidates[..1],
            output.as_mut_view(),
        );
        assert_eq!(output.as_ref(), candidates[0].as_ref());
    }

    cmux(&[], default.as_view(), &[], output.as_mut_view());
    assert_eq!(output.as_ref(), default.as_ref());
}

#[test]
fn ntt_cmux_checks_shapes_before_each_pair_and_recovers() {
    let modulus = BarrettModulus::new(257u32);
    let basis = ApproxSignedBasis::new(Some(257u32), DecompositionBaseLog::new(3), None);
    let table = U32NttTable::new(POLY_LENGTH, modulus).unwrap();
    let control = unit_ngsw(&basis).into_ntt_form(&table);
    let control_len = control.as_ref().len();
    let mut storage = control.into_inner();
    storage.push(0); // Also exercise an oversized gadget rather than a short slice only.
    let mut workspace = NttNtruExternalProductWorkspace::new(POLY_LENGTH);
    check_shapes(control_len, |lengths, default, candidates, output| {
        NttNgsw::cmux_k_to(
            lengths.iter().map(|&len| NttNgsw::new(&storage[..len])),
            default,
            candidates,
            output,
            &basis,
            modulus,
            &table,
            &mut workspace,
        );
    });
}

// Bind one FFT instance to the native-torus control and all recovery calls.
pub(super) fn check_fourier<Table: FftTable>(table: &Table) {
    let basis = ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None);
    let mut fft = FftEngine::new(table);
    let mut control = FourierNgswOwned::zero(basis.level_count().get() * N / 2);
    unit_ngsw(&basis).write_fourier_form(&mut control, &mut fft);
    let control_len = control.as_ref().len();
    let mut storage = control.as_ref().to_vec();
    storage.push(Complex64::default());
    let mut workspace = FourierNtruExternalProductWorkspace::new(POLY_LENGTH);
    check_shapes(control_len, |lengths, default, candidates, output| {
        FourierNgsw::cmux_k_to(
            lengths.iter().map(|&len| FourierNgsw::new(&storage[..len])),
            default,
            candidates,
            output,
            &basis,
            &mut fft,
            &mut workspace,
        );
    });
}
