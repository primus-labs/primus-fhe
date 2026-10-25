//! Independent nearest-center oracles for ordinary, interleaved and odd-domain LUTs.

use std::cell::{Cell, RefCell};

use primus_encoding::RoundedCodec;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;
use primus_tfhe::{LookupTableCompiler, LookupTableError};

const N: usize = 32;
const Q_IN: u32 = 97;
const Q_OUT: u32 = 257;

fn encode(message: u32, q: u32, t: u32) -> u32 {
    ((u64::from(message) * u64::from(q) + u64::from(t / 2)) / u64::from(t)) as u32 % q
}

fn center(message: u32, t: u32, period: usize) -> i32 {
    ((u64::from(encode(message, Q_IN, t)) * period as u64 + u64::from(Q_IN / 2)) / u64::from(Q_IN)
        % period as u64) as i32
}

fn negate(value: u32) -> u32 {
    (Q_OUT - value) % Q_OUT
}

/// Search all declared centers; ties select the larger position. This avoids
/// reproducing the compiler's interval endpoints or fill loops.
fn nearest(centers: &[(i32, u32)], position: usize) -> u32 {
    centers
        .iter()
        .min_by_key(|&&(x, _)| ((x - position as i32).abs(), -x))
        .unwrap()
        .1
}

#[test]
fn front_half_and_interleaved_intervals_match_nearest_centers() {
    let input = RoundedCodec::new(8, BarrettModulus::new(Q_IN));
    // Different input/output message AND ciphertext moduli.
    let output = RoundedCodec::new(5, BarrettModulus::new(Q_OUT));
    let compiler = LookupTableCompiler::try_new(
        PolyLength::new(N),
        &input,
        BarrettModulus::new(Q_OUT),
        &output,
    )
    .unwrap();
    for count in [1usize, 3] {
        let calls = RefCell::new(Vec::new());
        let function = |m: usize, j: usize| {
            calls.borrow_mut().push((m, j));
            ((2 * m + j + 1) % 5) as u32
        };
        let coefficients = if count == 1 {
            compiler
                .compile_fn(|m| function(m, 0))
                .unwrap()
                .polynomial()
                .as_ref()
                .to_vec()
        } else {
            compiler
                .compile_interleaved_fn(count, function)
                .unwrap()
                .polynomial()
                .as_ref()
                .to_vec()
        };
        assert_eq!(
            *calls.borrow(),
            (0..4)
                .flat_map(|m| (0..count).map(move |j| (m, j)))
                .collect::<Vec<_>>()
        );
        let stride = count.next_power_of_two();
        for lane in 0..stride {
            let value = |m| {
                if lane < count {
                    encode(((2 * m + lane + 1) % 5) as u32, Q_OUT, 5)
                } else {
                    0
                }
            };
            let mut centers: Vec<_> = (0..4)
                .map(|m| (center(m, 8, 2 * N / stride), value(m as usize)))
                .collect();
            centers.push(((N / stride) as i32, negate(value(0))));
            for position in 0..N / stride {
                assert_eq!(
                    coefficients[position * stride + lane],
                    nearest(&centers, position)
                );
            }
        }
    }
}

#[test]
fn front_half_capacity_uses_the_programmed_prefix() {
    let n = PolyLength::new(N);
    let q = BarrettModulus::new(Q_IN);
    let ring = BarrettModulus::new(Q_OUT);
    // t=65 has 33 front-half messages, but this program uses only two.
    // Their actual rounded centers are 0 and 1; the terminal center is 2.
    let table = primus_tfhe::LookupTable::try_new(2, n, 65, q, ring, |m| Ok(7 + m as u32)).unwrap();
    assert_eq!(&table.polynomial().as_ref()[..2], &[7, 8]);
    assert!(
        table.polynomial().as_ref()[2..]
            .iter()
            .all(|&v| v == Q_OUT - 7)
    );

    // Compiling the complete domain still rejects insufficient capacity before F.
    let input = RoundedCodec::new(65, q);
    let output = RoundedCodec::new(8, ring);
    let compiler = LookupTableCompiler::try_new(n, &input, ring, &output).unwrap();
    assert!(matches!(
        compiler.compile_fn(|_| panic!("capacity must be checked before F")),
        Err(LookupTableError::PlaintextDomainTooLarge {
            domain_len: 33,
            coefficients_per_output: N,
        })
    ));

    // A prefix fitting N can still collide: at t=96, centers 1 and 2 both round to 1.
    assert!(matches!(
        primus_tfhe::LookupTable::try_new(2, n, 96, q, ring, |_| Ok(7)),
        Err(LookupTableError::RotationCenterCollision { .. })
    ));
}

#[test]
fn odd_full_domain_folds_signs_and_signed_seam() {
    let input = RoundedCodec::new(5, BarrettModulus::new(Q_IN));
    let output = RoundedCodec::new(8, BarrettModulus::new(Q_OUT));
    let compiler = LookupTableCompiler::try_new(
        PolyLength::new(N),
        &input,
        BarrettModulus::new(Q_OUT),
        &output,
    )
    .unwrap();
    let table = compiler
        .compile_odd_full_domain_fn(|m| ((m * m + 1) % 8) as u32)
        .unwrap();
    let mut centers = Vec::new();
    for m in 0..5 {
        let exponent = center(m, 5, 2 * N);
        let value = encode((m * m + 1) % 8, Q_OUT, 8);
        // Negacyclic extension supplies signed copies on both sides of [0,N).
        for turn in -2i32..=1 {
            centers.push((
                exponent + turn * N as i32,
                if turn % 2 == 0 { value } else { negate(value) },
            ));
        }
    }
    for (position, &value) in table.polynomial().as_ref().iter().enumerate() {
        assert_eq!(value, nearest(&centers, position));
    }
}

#[test]
fn compiler_rejects_mismatched_domains_before_callback() {
    let q = BarrettModulus::new(Q_IN);
    let input = RoundedCodec::new(16, q);
    let output = RoundedCodec::new(8, BarrettModulus::new(Q_OUT));
    assert!(matches!(
        LookupTableCompiler::try_new(PolyLength::new(N), &input, q, &output),
        Err(LookupTableError::OutputModulusMismatch)
    ));
    let compiler = LookupTableCompiler::try_new(
        PolyLength::new(N),
        &input,
        BarrettModulus::new(Q_OUT),
        &output,
    )
    .unwrap();
    let calls = Cell::new(0);
    let result = compiler.compile_interleaved_fn(5, |_, _| {
        calls.set(calls.get() + 1);
        0
    });
    assert!(matches!(
        result,
        Err(LookupTableError::PlaintextDomainTooLarge { .. })
    ));
    assert_eq!(calls.get(), 0);
    assert!(matches!(
        compiler.compile_slice(&[8]),
        Err(LookupTableError::DomainLengthMismatch { .. })
    ));
    assert!(matches!(
        compiler.compile_fn(|m| if m == 2 { 8 } else { 0 }),
        Err(LookupTableError::OutputOutOfRange { input: 2 })
    ));
}

/// Evaluate X^-E directly in Z_Q[X]/(X^N+1), independently of the compiler's
/// fill loops. Check every protected rotation, effective level and padding lane.
fn check_msb_program<M: primus_reduce::RingContext<u32>>(
    modulus: M,
    log_basis: u32,
    levels: usize,
) {
    use primus_decompose::{
        DecompositionBaseLog, DecompositionLevelCount, primitive::ApproxSignedBasis,
    };
    use primus_tfhe::{CbsInputEncoding, CircuitBootstrapLookupTable};
    let basis = ApproxSignedBasis::new(
        modulus.explicit_value(),
        DecompositionBaseLog::new(log_basis),
        Some(DecompositionLevelCount::new(levels)),
    );
    let input = RoundedCodec::new(2, BarrettModulus::new(Q_IN));
    let q = modulus.explicit_value().map_or(1u64 << 32, u64::from);
    // Identity, NOT and both constants exercise slope and nonzero intercept.
    for values in [[0u32, 1], [1, 0], [0, 0], [1, 1]] {
        let calls = RefCell::new(Vec::new());
        let lut = CircuitBootstrapLookupTable::try_from_fn(
            PolyLength::new(N),
            &input,
            CbsInputEncoding::MsbBoolean,
            &basis,
            modulus,
            |i| {
                calls.borrow_mut().push(i);
                values[i]
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), [0, 1]);
        let stride = lut.padded_output_count();
        let weights: Vec<_> = basis.scalar_iter().collect();
        for e in (0..2 * N).step_by(stride) {
            if e == N / 2 || e == N + N / 2 {
                continue;
            } // Strict protection boundaries.
            let bit = usize::from(e > N / 2 && e < N + N / 2);
            for lane in 0..stride {
                let source = (lane + e) % (2 * N);
                let coefficient = u64::from(lut.polynomial().as_ref()[source % N]);
                let rotated = if source < N {
                    coefficient
                } else {
                    (q - coefficient) % q
                };
                let offset = lut.post_trace_offsets().get(lane).copied().unwrap_or(0);
                let expected =
                    u64::from(weights.get(lane).copied().unwrap_or(0)) * u64::from(values[bit]) % q;
                assert_eq!(
                    (rotated + u64::from(offset)) % q,
                    expected,
                    "E={e}, lane={lane}, F={values:?}"
                );
            }
        }
    }
}

#[test]
fn msb_cbs_negacyclic_geometry_and_modular_halves() {
    // Prime full decomposition includes odd g=1; native deliberately leaves a bit.
    check_msb_program(BarrettModulus::new(257), 3, 3);
    check_msb_program(primus_modulus::NativeModulus::<u32>::new(), 8, 3);
}

#[test]
fn msb_cbs_rejects_inexact_halves_and_unprotected_centers() {
    use primus_decompose::{
        DecompositionBaseLog, DecompositionLevelCount, primitive::ApproxSignedBasis,
    };
    use primus_tfhe::{CbsInputEncoding, CircuitBootstrapLookupTable};
    let native = primus_modulus::NativeModulus::<u32>::new();
    let input = RoundedCodec::new(2, BarrettModulus::new(Q_IN));
    let full = ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None);
    let result = CircuitBootstrapLookupTable::try_from_fn(
        PolyLength::new(N),
        &input,
        CbsInputEncoding::MsbBoolean,
        &full,
        native,
        |_| panic!("invalid scales must be rejected before F"),
    );
    assert!(matches!(result, Err(LookupTableError::OddMsbGadgetScale)));
    // q=3 rounds bit 1 to 2; stride 16 then maps its center onto 3N/2.
    let narrow = RoundedCodec::new(2, BarrettModulus::new(3));
    let basis = ApproxSignedBasis::new(
        None,
        DecompositionBaseLog::new(2),
        Some(DecompositionLevelCount::new(9)),
    );
    let result = CircuitBootstrapLookupTable::try_from_fn(
        PolyLength::new(N),
        &narrow,
        CbsInputEncoding::MsbBoolean,
        &basis,
        native,
        |_| panic!("invalid geometry must be rejected before F"),
    );
    assert!(matches!(result, Err(LookupTableError::InvalidMsbGeometry)));
}
