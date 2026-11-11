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
    let small = Table::new(PolyLength::new(32));
    offset_roundtrip(&small);
    concurrent_roundtrip(&small);
    offset_roundtrip(&Table::new(PolyLength::new(64)));
}

fn offset_roundtrip<Table: FftTable>(table: &Table) {
    let n = table.poly_length().get();
    let mut engine = FftEngine::new(table);
    // Offset aligned allocations so the public slices have only element alignment.
    let input = AVec::<u32>::from_iter(CACHELINE_ALIGN, (0..=n).map(|i| (i as i32 - 13) as u32));
    let mut fourier = avec![Complex64::default(); table.fourier_length() + 1];
    let mut output = avec![0u32; n + 1];
    engine.forward_as_torus(&input[1..], &mut fourier[1..]);
    engine.backward_as_torus(&fourier[1..], &mut output[1..]);
    assert_eq!(output[1..], input[1..]);
}

fn concurrent_roundtrip<Table: FftTable>(table: &Table) {
    // Only the immutable plan is shared; each worker owns its phase workspace.
    std::thread::scope(|scope| {
        for offset in 0..2u32 {
            scope.spawn(move || {
                let mut engine = FftEngine::new(table);
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
