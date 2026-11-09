//! Rank-one square SS: independent physical-ciphertext and residual oracle.
use primus_decompose::{DecompositionBaseLog, DecompositionConfig, DecompositionLevelCount};
use primus_glwe::{
    GlevParameters, GlweParameters, GlweSecretKey, NttGlweGadgetEncryptWorkspace,
    NttGlweSchemeSwitchKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{
    GlweDimension, ggsw::NttGgsw, glev::Glev, workspace::NttGlweExternalProductWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U64NttTable};
use primus_poly::Polynomial;
use primus_shape::PolyLength;
use rand::{RngExt, SeedableRng, rngs::StdRng};

const N: usize = 32;
const Q: u64 = 1_125_899_906_826_241;

fn add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % Q as u128) as u64
}

fn sub(a: u64, b: u64) -> u64 {
    ((a as u128 + Q as u128 - b as u128) % Q as u128) as u64
}

fn mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % Q as u128) as u64
}

fn product(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut r = vec![0; N];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            let x = mul(a, b);
            let k = (i + j) % N;
            r[k] = if i + j < N {
                add(r[k], x)
            } else {
                sub(r[k], x)
            };
        }
    }
    r
}

fn phase(c: &[u64], s: &[u64]) -> Vec<u64> {
    c[N..]
        .iter()
        .zip(product(&c[..N], s))
        .map(|(&b, a)| sub(b, a))
        .collect()
}

// Separate integer implementation of the actual odd-Q wrap/carry contract.
fn digits(a: &[u64], levels: usize) -> Vec<Vec<u64>> {
    let b = 5;
    let radix = 1 << b;
    let drop = 50 - b * levels;
    let threshold = (0..levels)
        .map(|j| ((radix / 2 - 1) as u64) << (j * b + drop))
        .sum::<u64>()
        + if drop == 0 { 1 } else { 1 << (drop - 1) };
    let mut result = vec![vec![0; N]; levels];
    for (i, &x) in a.iter().enumerate() {
        let value = x + if x >= threshold { (1u64 << 50) - Q } else { 0 };
        let mut carry = drop > 0 && (value & (1 << (drop - 1))) != 0;
        for (j, row) in result.iter_mut().enumerate() {
            let raw = ((value >> (drop + j * b)) & (radix - 1) as u64) + u64::from(carry);
            carry = raw >= radix as u64 / 2;
            row[i] = if carry {
                if raw == radix as u64 {
                    0
                } else {
                    Q + raw - radix as u64
                }
            } else {
                raw
            };
        }
    }
    result
}

#[test]
fn square_matches_full_coefficient_oracle_with_offsets_and_residuals() {
    let modulus = BarrettModulus::new(Q);
    let table = U64NttTable::new(PolyLength::new(N), modulus).unwrap();
    let params = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(N),
        8,
        modulus,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let signed: Vec<i64> = (0..N).map(|i| [-1, 0, 1][(i * 7 + i / 3) % 3]).collect();
    let s: Vec<u64> = signed
        .iter()
        .map(|&x| {
            if x < 0 {
                Q - x.unsigned_abs()
            } else {
                x as u64
            }
        })
        .collect();
    let secret = GlweSecretKey::new(signed, params.size(), SecretKeyDistr::UniformTernary);
    let ntt_secret = NttGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let decomp = |l| DecompositionConfig {
        log_basis: DecompositionBaseLog::new(5),
        level_count: Some(DecompositionLevelCount::new(l)),
    };
    let output = GlevParameters::with_glwe_params(&params, decomp(3));
    let mut rng = StdRng::seed_from_u64(742931);
    for levels in [9, 10] {
        let key_params = GlevParameters::with_glwe_params(&params, decomp(levels));
        let mut kg = NttGlweGadgetEncryptWorkspace::new(key_params.size());
        // Rebuild the old GGSW(-s) with the same RNG seed. Its first GLev is the
        // square material, so the oracle also checks the compact generator's
        // diagonal sign, sampling order and full physical ciphertext.
        let mut reference_rng = StdRng::seed_from_u64(742931 + levels as u64);
        let mut key_rng = StdRng::seed_from_u64(742931 + levels as u64);
        let negated: Vec<_> = s.iter().map(|&v| if v == 0 { 0 } else { Q - v }).collect();
        let mut all: NttGgsw<Vec<u64>> = NttGgsw::zero(key_params.ggsw_len());
        ntt_secret.encrypt_ggsw_to(
            &Polynomial::new(negated),
            &mut all,
            &key_params,
            &table,
            &mut reference_rng,
            &mut kg,
        );
        let all = all.into_coeff_form(&table);
        let key = NttGlweSchemeSwitchKey::generate(
            &secret,
            &ntt_secret,
            output.size(),
            &key_params,
            &table,
            &mut key_rng,
            &mut kg,
        );
        let mut ep = NttGlweExternalProductWorkspace::new(output.size());
        for pattern in 0..4 {
            for offset in [0, 1, Q / 8, Q - 1] {
                let mut data: Vec<u64> = (0..output.glev_len())
                    .map(|i| match pattern {
                        0 => 0,
                        1 => Q - 1,
                        2 => ((i as u64) * 31 + Q / 2) % Q,
                        _ => rng.random::<u64>() % Q,
                    })
                    .collect();
                for lane in data.as_chunks_mut::<{ 2 * N }>().0 {
                    lane[N] = add(lane[N], offset);
                }
                let input = Glev::new(data);
                let mut control = NttGgsw::new(vec![11; output.ggsw_len()]);
                ep.with_rebound(key_params.size(), |ep| {
                    key.apply_to(&input, &mut control, modulus, &table, ep)
                });
                assert_eq!(ep.size(), output.size());
                let control = control.into_coeff_form(&table);
                for (l, lane) in input.iter_glwe(2 * N).enumerate() {
                    let c = lane.as_ref();
                    let mask_digits = digits(&c[..N], levels);
                    let mut square = vec![0; 2 * N];
                    for (j, digit) in mask_digits.iter().enumerate() {
                        for component in 0..2 {
                            let ka = &all.as_ref()
                                [j * 2 * N + component * N..j * 2 * N + (component + 1) * N];
                            let pa = product(digit, ka);
                            for i in 0..N {
                                square[component * N + i] = add(square[component * N + i], pa[i]);
                            }
                        }
                    }
                    for i in 0..N {
                        square[i] = add(square[i], c[N + i]);
                    }
                    assert_eq!(&control.as_ref()[l * 2 * N..(l + 1) * 2 * N], square);
                    assert_eq!(
                        &control.as_ref()
                            [output.glev_len() + l * 2 * N..output.glev_len() + (l + 1) * 2 * N],
                        c
                    );
                    let mut reconstructed = vec![0; N];
                    let mut key_error = vec![0; N];
                    let s2 = product(&s, &s);
                    for (j, scalar) in key_params.basis().scalar_iter().enumerate() {
                        for i in 0..N {
                            reconstructed[i] =
                                add(reconstructed[i], mul(scalar, mask_digits[j][i]));
                        }
                        let kp = phase(&all.as_ref()[j * 2 * N..(j + 1) * 2 * N], &s);
                        let eta: Vec<_> = kp
                            .iter()
                            .zip(&s2)
                            .map(|(&p, &v)| sub(p, mul(scalar, v)))
                            .collect();
                        for (i, v) in product(&mask_digits[j], &eta).iter().enumerate() {
                            key_error[i] = add(key_error[i], *v);
                        }
                    }
                    let epsilon: Vec<_> = c[..N]
                        .iter()
                        .zip(reconstructed)
                        .map(|(&x, r)| sub(x, r))
                        .collect();
                    let input_phase = phase(c, &s);
                    let propagated_phase = product(&s, &input_phase);
                    let residual_term = product(&s2, &epsilon);
                    let expected: Vec<_> = (0..N)
                        .map(|i| {
                            add(
                                sub(sub(0, propagated_phase[i]), residual_term[i]),
                                key_error[i],
                            )
                        })
                        .collect();
                    assert_eq!(phase(&square, &s), expected);
                }
            }
        }
    }
}
