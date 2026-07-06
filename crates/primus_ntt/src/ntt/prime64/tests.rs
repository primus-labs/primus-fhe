use super::*;
use primus_modulus::BarrettModulus;
use rand::RngExt;

const Q: u64 = 132120577;
const N: usize = 1024;

fn make_table(log_n: u32, q: u64) -> U64NttTable {
    let modulus = <BarrettModulus<u64>>::new(q);
    U64NttTable::new(log_n, modulus).unwrap()
}

/// Check that lazy forward output is in `[0, 4q)`.
#[test]
fn test_lazy_forward_range() {
    let table = make_table(10, Q);
    let mut data = vec![0u64; N];

    let mut rng = rand::rng();
    for x in &mut data {
        *x = rng.random_range(0..4 * Q);
    }

    table.lazy_transform_slice(&mut data);

    for &v in &data {
        assert!(v < 4 * Q, "lazy forward output {v} >= 4q");
    }
}

/// Check that lazy inverse output is in `[0, 2q)`.
#[test]
fn test_lazy_inverse_range() {
    let table = make_table(10, Q);
    let mut data = vec![0u64; N];

    let mut rng = rand::rng();
    for x in &mut data {
        *x = rng.random_range(0..2 * Q);
    }

    table.lazy_inverse_transform_slice(&mut data);

    for &v in &data {
        assert!(v < 2 * Q, "lazy inverse output {v} >= 2q");
    }
}

/// Round-trip: forward + inverse restores original.
#[test]
fn test_round_trip() {
    let ns = [8u64, 16, 32, 64, 128, 256, 512, 1024];
    let mut rng = rand::rng();

    for &n_val in &ns {
        let log_n = n_val.trailing_zeros();
        let n = 1usize << log_n;

        // Need q ≡ 1 mod 2n for a primitive 2n-th root to exist
        if !(Q - 1).is_multiple_of(2 * n as u64) {
            continue;
        }

        let table = make_table(log_n, Q);

        let mut data: Vec<u64> = (0..n).map(|_| rng.random_range(0..Q)).collect();
        let original = data.clone();

        table.transform_slice(&mut data);
        table.inverse_transform_slice(&mut data);

        assert_eq!(data, original, "round-trip failed for N={n_val}");
    }
}

/// Cross-check with `UintNttTable<u64>`.
#[test]
fn test_cross_check_against_uint_table() {
    use crate::ntt::UintNttTable;

    let q_mod = <BarrettModulus<u64>>::new(Q);

    let u64_table = make_table(10, Q);
    let uint_table = UintNttTable::<u64>::new(10, q_mod).unwrap();

    let mut rng = rand::rng();

    // Test lazy forward
    {
        let mut data64 = vec![0u64; N];
        let mut data_uint = vec![0u64; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data64[i] = v;
            data_uint[i] = v;
        }
        u64_table.lazy_transform_slice(&mut data64);
        uint_table.lazy_transform_slice(&mut data_uint);

        for i in 0..N {
            assert_eq!(
                data64[i] % Q,
                data_uint[i] % Q,
                "lazy forward mismatch at index {i}"
            );
        }
    }

    // Test canonical forward
    {
        let mut data64 = vec![0u64; N];
        let mut data_uint = vec![0u64; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data64[i] = v;
            data_uint[i] = v;
        }
        u64_table.transform_slice(&mut data64);
        uint_table.transform_slice(&mut data_uint);

        assert_eq!(data64, data_uint, "canonical forward mismatch");
    }

    // Test lazy inverse
    {
        let mut data64 = vec![0u64; N];
        let mut data_uint = vec![0u64; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data64[i] = v;
            data_uint[i] = v;
        }
        u64_table.lazy_inverse_transform_slice(&mut data64);
        uint_table.lazy_inverse_transform_slice(&mut data_uint);

        for i in 0..N {
            assert_eq!(
                data64[i] % Q,
                data_uint[i] % Q,
                "lazy inverse mismatch at index {i}"
            );
        }
    }

    // Test canonical inverse
    {
        let mut data64 = vec![0u64; N];
        let mut data_uint = vec![0u64; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data64[i] = v;
            data_uint[i] = v;
        }
        u64_table.inverse_transform_slice(&mut data64);
        uint_table.inverse_transform_slice(&mut data_uint);

        assert_eq!(data64, data_uint, "canonical inverse mismatch");
    }

    // Test monomial transform
    {
        let coeff = rng.random_range(1..Q);
        let degree = rng.random_range(1..N);
        let mut data64 = vec![0u64; N];
        let mut data_uint = vec![0u64; N];
        u64_table.transform_monomial(coeff, degree, &mut data64);
        uint_table.transform_monomial(coeff, degree, &mut data_uint);

        assert_eq!(
            data64, data_uint,
            "monomial mismatch, coeff={coeff}, degree={degree}"
        );
    }
}

/// Cross-check against `UintNttTable` for three modulus sizes that
/// exercise different Barrett shift widths (32 / 52 / 64).
#[test]
fn test_cross_check_barrett_regimes() {
    use crate::ntt::UintNttTable;

    let test_moduli = [536813569u64, 562949953392641, 1152921504606830593];
    let n = 1024;
    let mut rng = rand::rng();

    for &q in &test_moduli {
        let q_mod = <BarrettModulus<u64>>::new(q);
        let u64_table = U64NttTable::new(10, q_mod).unwrap();
        let uint_table = UintNttTable::<u64>::new(10, q_mod).unwrap();

        let mut data64: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
        let mut data_uint = data64.clone();

        u64_table.transform_slice(&mut data64);
        uint_table.transform_slice(&mut data_uint);
        assert_eq!(data64, data_uint, "forward mismatch for q={q}");

        u64_table.inverse_transform_slice(&mut data64);
        uint_table.inverse_transform_slice(&mut data_uint);
        assert_eq!(data64, data_uint, "inverse mismatch for q={q}");
    }
}

/// Round-trip + cross-check with `UintNttTable<u64>` for large moduli.
#[test]
fn test_large_modulus_round_trip() {
    use crate::ntt::UintNttTable;

    let test_moduli = [562949953392641u64, 1152921504606830593];
    let n = 1024;
    let mut rng = rand::rng();

    for &q in &test_moduli {
        let q_mod = <BarrettModulus<u64>>::new(q);
        let u64_table = U64NttTable::new(10, q_mod).unwrap();
        let uint_table = UintNttTable::<u64>::new(10, q_mod).unwrap();

        // Round-trip
        let mut data: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
        let original = data.clone();
        u64_table.transform_slice(&mut data);
        u64_table.inverse_transform_slice(&mut data);
        assert_eq!(data, original, "round-trip failed for q={q}");

        // Cross-check forward
        let mut data_u64: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
        let mut data_uint = data_u64.clone();
        u64_table.transform_slice(&mut data_u64);
        uint_table.transform_slice(&mut data_uint);
        assert_eq!(data_u64, data_uint, "forward mismatch vs uint for q={q}");

        // Cross-check inverse
        u64_table.inverse_transform_slice(&mut data_u64);
        uint_table.inverse_transform_slice(&mut data_uint);
        assert_eq!(data_u64, data_uint, "inverse mismatch vs uint for q={q}");
    }
}

/// Verify that Barrett-32 and Barrett-64 scalar paths produce identical
/// results for a low‑q prime.  This catches bugs in the `BIT_SHIFT`
/// const‑generic dispatch before any SIMD backend runs.
#[test]
fn test_bit_shift_consensus() {
    let q = 132120577u64; // 27‑bit prime → low_q = true
    let q_mod = <BarrettModulus<u64>>::new(q);
    let table = U64NttTable::new(10, q_mod).unwrap();
    let mut rng = rand::rng();

    let n = table.n();
    let mut data32: Vec<u64> = (0..n).map(|_| rng.random_range(0..q)).collect();
    let mut data64 = data32.clone();

    // Forward: both paths must agree modulo q
    table.scalar_forward_transform::<32>(&mut data32, 1);
    table.scalar_forward_transform::<64>(&mut data64, 1);
    for i in 0..n {
        assert_eq!(
            data32[i], data64[i],
            "forward BIT_SHIFT=32 vs 64 mismatch at index {i}"
        );
    }

    // Inverse: both paths must agree modulo q
    table.scalar_inverse_transform::<32>(&mut data32, 1);
    table.scalar_inverse_transform::<64>(&mut data64, 1);
    for i in 0..n {
        assert_eq!(
            data32[i], data64[i],
            "inverse BIT_SHIFT=32 vs 64 mismatch at index {i}"
        );
    }
}
