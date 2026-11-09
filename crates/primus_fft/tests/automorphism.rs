#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_fft::{Complex64, FftEngine, FftTable};
use primus_shape::PolyLength;

fn check_automorphism<Table: FftTable>() {
    // Check coefficient signs and packed conjugation. The private TFHE-FFT
    // test forces recursive layouts; a large auto-planned transform cannot
    // guarantee that the planner selects any particular layout.
    for log_n in [5u32, 6] {
        let table = Table::new(PolyLength::new(1usize << log_n));
        let mut fft = FftEngine::new(&table);
        let n = table.poly_length().get();
        let input: Vec<u32> = (0..n)
            .map(|i| (i as u32).wrapping_mul(2_654_435_761))
            .collect();
        let mut spectrum = vec![Complex64::default(); n / 2];
        let mut permuted = spectrum.clone();
        let mut output = vec![0u32; n];
        fft.forward_as_torus(&input, &mut spectrum);
        for degree in [1, 3, 5, n + 1, 2 * n - 1] {
            let map = table.automorphism_map(degree);
            assert_eq!(map.len(), n / 2);
            for (output, &(source, conjugate)) in permuted.iter_mut().zip(&map) {
                *output = if conjugate {
                    spectrum[source].conj()
                } else {
                    spectrum[source]
                };
            }
            fft.backward_as_torus(&permuted, &mut output);
            let mut expected = vec![0; n];
            for (i, &value) in input.iter().enumerate() {
                let dest = i * degree % (2 * n);
                expected[dest % n] = if dest < n {
                    value
                } else {
                    value.wrapping_neg()
                };
            }
            assert_eq!(output, expected, "N={n}, degree={degree}");
        }
        for degree in [0, 2, 2 * n + 1] {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || table.automorphism_map(degree)
                ))
                .is_err()
            );
        }
    }
}

#[test]
fn enabled_backend_maps_match_coefficient_automorphisms() {
    #[cfg(feature = "rustfft")]
    check_automorphism::<RustFftTable>();
    #[cfg(feature = "tfhe-fft")]
    check_automorphism::<TfheFftTable>();
}
