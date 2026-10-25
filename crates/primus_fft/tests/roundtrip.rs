#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

use aligned_vec::{AVec, CACHELINE_ALIGN, avec};
#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_fft::{Complex64, FftEngine, FftTable};
use primus_shape::PolyLength;

fn roundtrip<Table: FftTable>() {
    // Minimum supported packing and a complete vector-sized buffer with offset slices.
    // Larger work buffers are exercised by zeroize.rs; convolution has its own oracle.
    for log_n in [5u32, 6] {
        let fft = Table::new(PolyLength::new(1usize << log_n));
        let mut engine = FftEngine::new(&fft);
        // Offset aligned allocations: public slices need only element alignment,
        // even though the table and its own workspace use cache-line alignment.
        let input = AVec::<u32>::from_iter(
            CACHELINE_ALIGN,
            (0..=fft.poly_length().get()).map(|i| (i as i32 - 13) as u32),
        );
        let mut fourier = avec![Complex64::default(); fft.fourier_length() + 1];
        let mut output = avec![0u32; fft.poly_length().get() + 1];
        engine.forward_as_torus(&input[1..], &mut fourier[1..]);
        engine.backward_as_torus(&fourier[1..], &mut output[1..]);
        assert_eq!(output[1..], input[1..]);
    }
}

fn concurrent_roundtrip<Table: FftTable>() {
    // Only the immutable plan is shared; each worker owns its phase workspace.
    let fft = Table::new(PolyLength::new(32));
    std::thread::scope(|scope| {
        for offset in 0..2u32 {
            let fft = &fft;
            scope.spawn(move || {
                let mut engine = FftEngine::new(fft);
                let input: Vec<u32> = (0..engine.poly_length().get())
                    .map(|index| (index as u32).wrapping_add(offset))
                    .collect();
                let mut fourier = vec![Complex64::default(); engine.fourier_length()];
                let mut output = vec![0u32; engine.poly_length().get()];
                engine.forward_as_torus(&input, &mut fourier);
                engine.backward_as_torus(&fourier, &mut output);
                assert_eq!(output, input);
            });
        }
    });
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_roundtrip() {
    roundtrip::<RustFftTable>();
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_roundtrip() {
    roundtrip::<TfheFftTable>();
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_shared_table_runs_with_independent_scratch() {
    concurrent_roundtrip::<RustFftTable>();
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_shared_table_runs_with_independent_scratch() {
    concurrent_roundtrip::<TfheFftTable>();
}
