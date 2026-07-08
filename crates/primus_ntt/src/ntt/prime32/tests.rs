use super::*;
use primus_modulus::BarrettModulus;
use rand::RngExt;

const Q: u32 = 132120577; // 27-bit prime, 1 mod 2048
const N: usize = 1024;

fn make_table(log_n: u32, q: u32) -> U32NttTable {
    let modulus = <BarrettModulus<u32>>::new(q);
    U32NttTable::new(log_n, modulus).unwrap()
}

/// Check that lazy forward output is in `[0, 4q)`.
#[test]
fn test_lazy_forward_range() {
    let table = make_table(10, Q);
    let mut data = vec![0u32; N];

    let mut rng = rand::rng();
    for x in &mut data {
        *x = rng.random_range(0..4 * Q);
    }

    let original = data.clone();
    table.lazy_transform_slice(&mut data);

    for &v in &data {
        assert!(v < 4 * Q, "lazy forward output {v} >= 4q");
    }
    assert_ne!(data, original);
}

/// Check that lazy inverse output is in `[0, 2q)`.
#[test]
fn test_lazy_inverse_range() {
    let table = make_table(10, Q);
    let mut data = vec![0u32; N];

    let mut rng = rand::rng();
    for x in &mut data {
        *x = rng.random_range(0..2 * Q);
    }

    table.lazy_inverse_transform_slice(&mut data);

    for &v in &data {
        assert!(v < 2 * Q, "lazy inverse output {v} >= 2q");
    }
}

/// Check canonical forward output is in `[0, q)`.
#[test]
fn test_canonical_forward_range() {
    let table = make_table(10, Q);
    let mut data = vec![0u32; N];

    let mut rng = rand::rng();
    for x in &mut data {
        *x = rng.random_range(0..Q);
    }

    table.transform_slice(&mut data);

    for &v in &data {
        assert!(v < Q, "canonical forward output {v} >= q");
    }
}

/// Check canonical inverse output is in `[0, q)`.
#[test]
fn test_canonical_inverse_range() {
    let table = make_table(10, Q);
    let mut data = vec![0u32; N];

    let mut rng = rand::rng();
    for x in &mut data {
        *x = rng.random_range(0..Q);
    }

    table.inverse_transform_slice(&mut data);

    for &v in &data {
        assert!(v < Q, "canonical inverse output {v} >= q");
    }
}

/// Cross-path: `[0, 4q)` input via `lazy_transform_slice` + reduce
/// matches `[0, q)` input via `transform_slice` modulo `q`.
#[test]
fn test_lazy_vs_canonical_forward() {
    let table = make_table(10, Q);
    let mut rng = rand::rng();

    let mut lazy_in: Vec<u32> = (0..N).map(|_| rng.random_range(0..4 * Q)).collect();
    let mut canonical_in: Vec<u32> = lazy_in.iter().map(|&x| x % Q).collect();

    table.lazy_transform_slice(&mut lazy_in);
    table.transform_slice(&mut canonical_in);

    for i in 0..N {
        assert_eq!(
            lazy_in[i] % Q,
            canonical_in[i],
            "lazy vs canonical forward mismatch at index {i}"
        );
    }
}

/// Round-trip: forward + inverse restores original.
#[test]
fn test_round_trip() {
    let ns = [8u32, 16, 32, 64, 128, 256, 512, 1024];
    let mut rng = rand::rng();

    for &n_val in &ns {
        let log_n = n_val.trailing_zeros();
        let n = 1usize << log_n;

        // Need q ≡ 1 mod 2n for a primitive 2n-th root to exist
        if !(Q as u64 - 1).is_multiple_of(2 * n as u64) {
            continue;
        }

        let table = make_table(log_n, Q);

        let mut data: Vec<u32> = (0..n).map(|_| rng.random_range(0..Q)).collect();
        let original = data.clone();

        table.transform_slice(&mut data);
        table.inverse_transform_slice(&mut data);

        assert_eq!(data, original, "round-trip failed for N={n_val}");
    }
}

/// Cross-check with `UintNttTable<u32>`.
#[test]
fn test_cross_check_against_uint_table() {
    use crate::ntt::UintNttTable;

    let q_mod = <BarrettModulus<u32>>::new(Q);

    let u32_table = make_table(10, Q);
    let uint_table = UintNttTable::<u32>::new(10, q_mod).unwrap();

    let mut rng = rand::rng();

    // Test lazy forward
    {
        let mut data32 = vec![0u32; N];
        let mut data_uint = vec![0u32; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data32[i] = v;
            data_uint[i] = v;
        }
        u32_table.lazy_transform_slice(&mut data32);
        uint_table.lazy_transform_slice(&mut data_uint);

        for i in 0..N {
            assert_eq!(
                data32[i] % Q,
                data_uint[i] % Q,
                "lazy forward mismatch at index {i}"
            );
        }
    }

    // Test canonical forward
    {
        let mut data32 = vec![0u32; N];
        let mut data_uint = vec![0u32; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data32[i] = v;
            data_uint[i] = v;
        }
        u32_table.transform_slice(&mut data32);
        uint_table.transform_slice(&mut data_uint);

        assert_eq!(data32, data_uint, "canonical forward mismatch");
    }

    // Test lazy inverse
    {
        let mut data32 = vec![0u32; N];
        let mut data_uint = vec![0u32; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data32[i] = v;
            data_uint[i] = v;
        }
        u32_table.lazy_inverse_transform_slice(&mut data32);
        uint_table.lazy_inverse_transform_slice(&mut data_uint);

        for i in 0..N {
            assert_eq!(
                data32[i] % Q,
                data_uint[i] % Q,
                "lazy inverse mismatch at index {i}"
            );
        }
    }

    // Test canonical inverse
    {
        let mut data32 = vec![0u32; N];
        let mut data_uint = vec![0u32; N];
        for i in 0..N {
            let v = rng.random_range(0..Q);
            data32[i] = v;
            data_uint[i] = v;
        }
        u32_table.inverse_transform_slice(&mut data32);
        uint_table.inverse_transform_slice(&mut data_uint);

        assert_eq!(data32, data_uint, "canonical inverse mismatch");
    }

    // Test monomial transform
    {
        let coeff = rng.random_range(1..Q);
        let degree = rng.random_range(1..N);
        let mut data32 = vec![0u32; N];
        let mut data_uint = vec![0u32; N];
        u32_table.transform_monomial(coeff, degree, &mut data32);
        uint_table.transform_monomial(coeff, degree, &mut data_uint);

        assert_eq!(
            data32, data_uint,
            "monomial mismatch, coeff={coeff}, degree={degree}"
        );
    }
}

/// Verify pre-expanded root layout matches the AVX lane patterns
/// (tests the builder directly, no SIMD hardware needed).
#[test]
fn test_builder_lane_order() {
    // Use a small N=64 and a known identity-like root pattern.
    // Each root = its bit-reversed index, modulo a dummy q.
    let n = 64;
    // dummy roots: roots[i] = i (for forward), inv_roots[i] = i + 100 (for inverse)
    let roots: Vec<u32> = (0..n).map(|i| i as u32).collect();
    let inv_roots: Vec<u32> = (0..n).map(|i| (i + 100) as u32).collect();

    // Build AVX2 forward/inverse
    let avx2_fwd = crate::ntt::prime32::avx2::precompute::build_avx2_roots_u32(n, &roots, false);
    let avx2_inv = crate::ntt::prime32::avx2::precompute::build_avx2_roots_u32(n, &inv_roots, true);

    // Basic sanity: non-empty and aligned
    assert!(
        !avx2_fwd.is_empty(),
        "avx2 forward roots should be non-empty for n=64"
    );
    assert!(
        avx2_fwd.len().is_multiple_of(8),
        "avx2 output must be multiple of 8 u32s"
    );

    // For n=64, the forward traversal:
    // T8 (t=32,16,8): ri goes from 1 to 8 (consumes roots[1..8])
    // T4 (t=4): ri starts at 8, n/16=4 chunks. Chunk 0: [roots[8]×4, roots[9]×4]
    assert_eq!(avx2_fwd[0], roots[8]);
    assert_eq!(avx2_fwd[4], roots[9]);

    // T2: after T4 (4 vectors × 8 u32 = 32 u32s), ri at 16.
    // Chunk 0: [roots[16],roots[16], roots[18],roots[18], roots[17],roots[17], roots[19],roots[19]]
    let t2_off = 4 * 8; // 4 T4 vectors × 8 u32 each
    assert_eq!(avx2_fwd[t2_off], roots[16]);
    assert_eq!(avx2_fwd[t2_off + 1], roots[16]); // w0 dup
    assert_eq!(avx2_fwd[t2_off + 2], roots[18]); // w2 → lanes 3,2
    assert_eq!(avx2_fwd[t2_off + 3], roots[18]);
    assert_eq!(avx2_fwd[t2_off + 4], roots[17]); // w1 → lanes 5,4
    assert_eq!(avx2_fwd[t2_off + 5], roots[17]);
    assert_eq!(avx2_fwd[t2_off + 6], roots[19]); // w3 → lanes 7,6
    assert_eq!(avx2_fwd[t2_off + 7], roots[19]);

    // T1: after T2, ri is 32. The new T1 load order is
    // [w0,w1,w4,w5,w2,w3,w6,w7] in low-to-high lanes.
    let t1_off = t2_off + 4 * 8;
    assert_eq!(avx2_fwd[t1_off], roots[32]);
    assert_eq!(avx2_fwd[t1_off + 1], roots[33]);
    assert_eq!(avx2_fwd[t1_off + 2], roots[36]);
    assert_eq!(avx2_fwd[t1_off + 3], roots[37]);
    assert_eq!(avx2_fwd[t1_off + 4], roots[34]);
    assert_eq!(avx2_fwd[t1_off + 5], roots[35]);
    assert_eq!(avx2_fwd[t1_off + 6], roots[38]);
    assert_eq!(avx2_fwd[t1_off + 7], roots[39]);
    assert_eq!(avx2_fwd.len(), 96); // T4 + T2 + T1: 3 × 4 vec × 8 u32

    // AVX2 inverse: T1 now starts at ri=1 and uses the same new lane order.
    assert_eq!(avx2_inv[0], inv_roots[1]);
    assert_eq!(avx2_inv[1], inv_roots[2]);
    assert_eq!(avx2_inv[2], inv_roots[5]);
    assert_eq!(avx2_inv[3], inv_roots[6]);
    assert_eq!(avx2_inv[4], inv_roots[3]);
    assert_eq!(avx2_inv[5], inv_roots[4]);
    assert_eq!(avx2_inv[6], inv_roots[7]);
    assert_eq!(avx2_inv[7], inv_roots[8]);

    // T2 follows T1. After 4 T1 vectors, ri is 33.
    let inv_t2_off = 4 * 8;
    assert_eq!(avx2_inv[inv_t2_off], inv_roots[33]);
    assert_eq!(avx2_inv[inv_t2_off + 2], inv_roots[35]);
    assert_eq!(avx2_inv[inv_t2_off + 4], inv_roots[34]);
    assert_eq!(avx2_inv[inv_t2_off + 6], inv_roots[36]);
    assert_eq!(avx2_inv.len(), 96); // T1 + T2 + T4: 3 × 4 vec × 8 u32

    // AVX512 forward: T16 (t=32,16) skip, ri=4. T8 at ri=4, 2 chunks.
    // Chunk 0: [roots[4]×8, roots[5]×8]
    let avx512_fwd =
        crate::ntt::prime32::avx512::precompute::build_avx512_roots_u32(n, &roots, false);
    assert!(!avx512_fwd.is_empty());
    assert!(avx512_fwd.len().is_multiple_of(16));
    assert_eq!(avx512_fwd[0], roots[4]);
    assert_eq!(avx512_fwd[8], roots[5]);

    // T4 starts after two T8 vectors. Chunk 0 keeps natural order:
    // [w0×4, w1×4, w2×4, w3×4].
    let avx512_t4_off = 2 * 16;
    assert_eq!(avx512_fwd[avx512_t4_off], roots[8]);
    assert_eq!(avx512_fwd[avx512_t4_off + 4], roots[9]);
    assert_eq!(avx512_fwd[avx512_t4_off + 8], roots[10]);
    assert_eq!(avx512_fwd[avx512_t4_off + 12], roots[11]);

    // T2 follows T4. New unpack order is
    // [w0,w0,w4,w4,w1,w1,w5,w5,w2,w2,w6,w6,w3,w3,w7,w7].
    let avx512_t2_off = avx512_t4_off + 2 * 16;
    assert_eq!(avx512_fwd[avx512_t2_off], roots[16]);
    assert_eq!(avx512_fwd[avx512_t2_off + 2], roots[20]);
    assert_eq!(avx512_fwd[avx512_t2_off + 4], roots[17]);
    assert_eq!(avx512_fwd[avx512_t2_off + 6], roots[21]);
    assert_eq!(avx512_fwd[avx512_t2_off + 8], roots[18]);
    assert_eq!(avx512_fwd[avx512_t2_off + 10], roots[22]);
    assert_eq!(avx512_fwd[avx512_t2_off + 12], roots[19]);
    assert_eq!(avx512_fwd[avx512_t2_off + 14], roots[23]);

    // T1 follows T2. New shuffle+unpack order is
    // [w0,w1,w8,w9,w2,w3,w10,w11,w4,w5,w12,w13,w6,w7,w14,w15].
    let avx512_t1_off = avx512_t2_off + 2 * 16;
    assert_eq!(avx512_fwd[avx512_t1_off], roots[32]);
    assert_eq!(avx512_fwd[avx512_t1_off + 1], roots[33]);
    assert_eq!(avx512_fwd[avx512_t1_off + 2], roots[40]);
    assert_eq!(avx512_fwd[avx512_t1_off + 3], roots[41]);
    assert_eq!(avx512_fwd[avx512_t1_off + 4], roots[34]);
    assert_eq!(avx512_fwd[avx512_t1_off + 5], roots[35]);
    assert_eq!(avx512_fwd[avx512_t1_off + 6], roots[42]);
    assert_eq!(avx512_fwd[avx512_t1_off + 7], roots[43]);
    assert_eq!(avx512_fwd.len(), 128); // T8 + T4 + T2 + T1: 4 × 2 vec × 16 u32

    // AVX512 inverse starts at T1, ri=1, with the same new T1 lane order.
    let avx512_inv =
        crate::ntt::prime32::avx512::precompute::build_avx512_roots_u32(n, &inv_roots, true);
    assert_eq!(avx512_inv[0], inv_roots[1]);
    assert_eq!(avx512_inv[1], inv_roots[2]);
    assert_eq!(avx512_inv[2], inv_roots[9]);
    assert_eq!(avx512_inv[3], inv_roots[10]);
    assert_eq!(avx512_inv[4], inv_roots[3]);
    assert_eq!(avx512_inv[5], inv_roots[4]);
    assert_eq!(avx512_inv[6], inv_roots[11]);
    assert_eq!(avx512_inv[7], inv_roots[12]);

    // T2 follows two inverse T1 vectors. ri is 33.
    let avx512_inv_t2_off = 2 * 16;
    assert_eq!(avx512_inv[avx512_inv_t2_off], inv_roots[33]);
    assert_eq!(avx512_inv[avx512_inv_t2_off + 2], inv_roots[37]);
    assert_eq!(avx512_inv[avx512_inv_t2_off + 4], inv_roots[34]);
    assert_eq!(avx512_inv[avx512_inv_t2_off + 6], inv_roots[38]);
    assert_eq!(avx512_inv.len(), 128); // T1 + T2 + T4 + T8: 4 × 2 vec × 16 u32
}
