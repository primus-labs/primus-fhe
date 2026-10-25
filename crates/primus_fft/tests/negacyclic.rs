#![cfg(any(feature = "rustfft", feature = "tfhe-fft"))]

#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(feature = "tfhe-fft")]
use primus_fft::TfheFftTable;
use primus_fft::{Complex64, FftEngine, FftTable};
use primus_shape::PolyLength;

// Independent O(N^2) convolution applies X^N = -1 with exact signed arithmetic.
fn negacyclic_reference(torus: &[u32], integer: &[u32]) -> Vec<u32> {
    let n = torus.len();
    let mut result = vec![0i128; n];
    for i in 0..n {
        for j in 0..n {
            let a = torus[i] as i32 as i128;
            let b = integer[j] as i32 as i128;
            if i + j < n {
                result[i + j] += a * b;
            } else {
                result[i + j - n] -= a * b;
            }
        }
    }
    result.into_iter().map(|x| x as u32).collect()
}

fn convolution<Table: FftTable>() {
    // Torus * integer has exactly one torus scale and one inverse normalization;
    // a round-trip cannot detect a normalization error in spectral products.
    let fft = Table::new(PolyLength::new(32));
    let n = fft.poly_length().get();
    let mut engine = FftEngine::new(&fft);
    let torus: Vec<u32> = (0..n).map(|i| (1000i32 - 31 * i as i32) as u32).collect();
    let integer: Vec<u32> = (0..n).map(|i| (i as i32 % 5 - 2) as u32).collect();
    let mut lhs = vec![Complex64::default(); n / 2];
    let mut rhs = vec![Complex64::default(); n / 2];
    engine.forward_as_torus(&torus, &mut lhs);
    engine.forward_as_integer(&integer, &mut rhs);
    for (x, y) in lhs.iter_mut().zip(rhs) {
        *x *= y;
    }
    let mut output = vec![0u32; n];
    engine.backward_as_torus(&lhs, &mut output);
    assert_eq!(output, negacyclic_reference(&torus, &integer));
}

#[cfg(feature = "rustfft")]
#[test]
fn rustfft_negacyclic_convolution() {
    convolution::<RustFftTable>();
}

#[cfg(feature = "tfhe-fft")]
#[test]
fn tfhe_fft_negacyclic_convolution() {
    convolution::<TfheFftTable>();
}
