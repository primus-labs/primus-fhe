//! Public encryption identities, reusable workspaces and transform/allocation budgets.

use primus_decompose::{
    DecompositionBaseLog, DecompositionLevelCount, big_integer::BigUintApproxSignedBasis,
};
use primus_distr::ErrorDistribution;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweEncryptionParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweDomain, DcrtGlwePublicKey, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_integer::{AsFrom, FheUint};
use primus_lattice::{GlweDimension, GlweSize, RnsGlweSize, ggsw::DcrtGgsw};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, NttError, NttTable, U32NttTable, U64NttTable};
use primus_poly::CrtPolynomial;
use primus_reduce::FieldContext;
use primus_rns::{RNSBase, Residues};
use primus_shape::PolyLength;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};
use zeroize::Zeroize;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
    static TRANSFORMS: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn record_allocation(pointer: *mut u8) {
    if !pointer.is_null() {
        let _ = ALLOCATIONS.try_with(|count| {
            if let Some(value) = count.get() {
                count.set(Some(value + 1));
            }
        });
    }
}

// SAFETY: All calls preserve System's pointers and layouts. Observation uses
// const-initialized thread-local Cells and never allocates or touches other tests.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies GlobalAlloc's valid layout.
        let pointer = unsafe { System.alloc(layout) };
        record_allocation(pointer);
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The allocation contract is forwarded unchanged.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record_allocation(pointer);
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: The original pointer/layout and requested size are forwarded.
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        record_allocation(pointer);
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: No memory is inspected; System receives the original arguments.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Observation;

impl Drop for Observation {
    fn drop(&mut self) {
        ALLOCATIONS.with(|count| count.set(None));
        TRANSFORMS.with(|count| count.set(None));
    }
}

fn observe<R>(operation: impl FnOnce() -> R) -> (R, usize, (usize, usize)) {
    ALLOCATIONS.with(|count| {
        assert!(count.get().is_none());
        count.set(Some(0));
    });
    TRANSFORMS.with(|count| count.set(Some((0, 0))));
    let guard = Observation;
    let result = operation();
    let allocations = ALLOCATIONS.with(|count| count.get().unwrap());
    let transforms = TRANSFORMS.with(|count| count.get().unwrap());
    drop(guard);
    (result, allocations, transforms)
}

struct CountedTable(U64NttTable);

impl NttTable for CountedTable {
    type ValueT = u64;

    fn new<M: FieldContext<u64>>(n: PolyLength, modulus: M) -> Result<Self, NttError<u64>> {
        U64NttTable::new(n, modulus).map(Self)
    }

    fn poly_length(&self) -> PolyLength {
        self.0.poly_length()
    }
    fn modulus(&self) -> u64 {
        self.0.modulus()
    }
    fn lazy_transform_slice(&self, values: &mut [u64]) {
        TRANSFORMS.with(|count| {
            if let Some((forward, inverse)) = count.get() {
                count.set(Some((forward + 1, inverse)));
            }
        });
        self.0.lazy_transform_slice(values);
    }
    fn lazy_inverse_transform_slice(&self, values: &mut [u64]) {
        TRANSFORMS.with(|count| {
            if let Some((forward, inverse)) = count.get() {
                count.set(Some((forward, inverse + 1)));
            }
        });
        self.0.lazy_inverse_transform_slice(values);
    }

    fn transform_slice(&self, values: &mut [u64]) {
        TRANSFORMS.with(|count| {
            if let Some((forward, inverse)) = count.get() {
                count.set(Some((forward + 1, inverse)));
            }
        });
        self.0.transform_slice(values);
    }

    fn inverse_transform_slice(&self, values: &mut [u64]) {
        TRANSFORMS.with(|count| {
            if let Some((forward, inverse)) = count.get() {
                count.set(Some((forward, inverse + 1)));
            }
        });
        self.0.inverse_transform_slice(values);
    }
}

fn mul_mod(left: u64, right: u64, q: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(q)) as u64
}

fn pow_mod(mut value: u64, mut exponent: u32, q: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul_mod(result, value, q);
        }
        value = mul_mod(value, value, q);
        exponent >>= 1;
    }
    result
}

// N=32 roots are fixed witnesses, not fetched from production NTT tables.
fn points(root: u64, q: u64) -> Vec<u64> {
    assert_eq!(pow_mod(root, 32, q), q - 1);
    (0usize..32)
        .map(|j| {
            pow_mod(
                root,
                (2 * (j.reverse_bits() >> (usize::BITS - 5)) + 1) as u32,
                q,
            )
        })
        .collect()
}

fn direct_transform(coefficients: &[u64], root: u64, q: u64) -> Vec<u64> {
    points(root, q)
        .into_iter()
        .map(|point| {
            coefficients.iter().rev().fold(0, |acc, &coefficient| {
                (mul_mod(acc, point, q) + coefficient) % q
            })
        })
        .collect()
}

fn direct_inverse(evaluations: &[u64], root: u64, q: u64) -> Vec<u64> {
    let inverse_n = modular_inverse(32, q);
    let inverse_points: Vec<_> = points(root, q)
        .into_iter()
        .map(|value| modular_inverse(value, q))
        .collect();
    (0..32)
        .map(|degree| {
            let sum = evaluations
                .iter()
                .zip(&inverse_points)
                .fold(0, |acc, (&value, &point)| {
                    (acc + mul_mod(value, pow_mod(point, degree, q), q)) % q
                });
            mul_mod(sum, inverse_n, q)
        })
        .collect()
}

fn modular_inverse(value: u64, q: u64) -> u64 {
    let (mut old_r, mut r) = (i128::from(q), i128::from(value));
    let (mut old_t, mut t) = (0i128, 1i128);
    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_t, t) = (t, old_t - quotient * t);
    }
    assert_eq!(old_r, 1);
    old_t.rem_euclid(i128::from(q)) as u64
}

fn convolution(mask: &[u64], secret: &[i64], q: u64) -> Vec<u64> {
    let mut result = vec![0i128; 32];
    for (i, &value) in mask.iter().enumerate() {
        for (j, &s) in secret.iter().enumerate() {
            let product = i128::from(value) * i128::from(s);
            result[(i + j) % 32] += if i + j < 32 { product } else { -product };
        }
    }
    result
        .into_iter()
        .map(|value| value.rem_euclid(i128::from(q)) as u64)
        .collect()
}

fn phase<T: FheUint>(ciphertext: &[T], secret: &[i64], moduli: &[u64], roots: &[u64]) -> Vec<u64> {
    let poly_len = 32 * moduli.len();
    let rank = secret.len() / 32;
    let mut result = Vec::new();
    for (limb, (&q, &root)) in moduli.iter().zip(roots).enumerate() {
        let coefficients = |component| {
            direct_inverse(
                &ciphertext[component * poly_len + limb * 32..][..32]
                    .iter()
                    .map(|&value| value.as_into())
                    .collect::<Vec<_>>(),
                root,
                q,
            )
        };
        let mut output = coefficients(rank);
        for component in 0..rank {
            for (value, product) in output.iter_mut().zip(convolution(
                &coefficients(component),
                &secret[component * 32..][..32],
                q,
            )) {
                *value = (*value + q - product) % q;
            }
        }
        result.extend(output);
    }
    result
}

fn centered_crt(first: u64, second: u64, moduli: &[u64]) -> i128 {
    let [q0, q1] = <[u64; 2]>::try_from(moduli).unwrap();
    let correction = mul_mod(
        (second + q1 - first % q1) % q1,
        modular_inverse(q0 % q1, q1),
        q1,
    );
    let value = u128::from(first) + u128::from(q0) * u128::from(correction);
    let product = u128::from(q0) * u128::from(q1);
    value as i128
        - if value > product / 2 {
            product as i128
        } else {
            0
        }
}

fn check_public<T, Table>(moduli_values: [T; 2], roots: [u64; 2])
where
    T: FheUint,
    BarrettModulus<T>: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let values: Vec<u64> = moduli_values.iter().map(|&value| value.as_into()).collect();
    let moduli = moduli_values.map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    let table = DcrtTable::<Table>::new(PolyLength::new(32), &moduli).unwrap();
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(2), PolyLength::new(32)), 2);
    let key_parameters = CrtGlweEncryptionParameters::try_with_error_distribution(
        size,
        &base,
        SecretKeyDistr::SparseTernary,
        ErrorDistribution::CenteredBinomial { eta: 1 },
    )
    .unwrap();
    let parameters = Arc::new(
        CrtGlweEncryptionParameters::try_with_error_distribution(
            size,
            &base,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 21 },
        )
        .unwrap(),
    );
    let domain = DcrtGlweDomain::try_new(&parameters, &base, &table).unwrap();
    let secret: Vec<i64> = (0..64).map(|i| (i % 3) as i64 - 1).collect();
    let coefficient_key = GlweSecretKey::<T>::new(
        secret
            .iter()
            .map(|&value| T::SignedInteger::as_from(value))
            .collect(),
        size.glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&coefficient_key, &table);
    let public = DcrtGlwePublicKey::new(
        &key,
        &key_parameters,
        &base,
        &table,
        &mut StdRng::seed_from_u64(51),
    );
    let message: Vec<i64> = (0..32).map(|i| (i % 7) as i64 - 3).collect();
    let encoded = CrtPolynomial::new(
        values
            .iter()
            .flat_map(|&q| {
                message
                    .iter()
                    .map(move |&value| T::as_from(i128::from(value).rem_euclid(i128::from(q))))
            })
            .collect::<Vec<_>>(),
    );
    let mut raw = public.try_bind_raw(&domain).unwrap();
    let mut zero = DcrtGlweCiphertext::new(vec![T::MAX; size.rns_glwe_len()]);
    let mut output = zero.clone();
    raw.encrypt_zeros_to(&mut zero, &mut StdRng::seed_from_u64(52));
    raw.encrypt_encoded_crt_to(&encoded, &mut output, &mut StdRng::seed_from_u64(52));
    let saved = output.as_ref().to_vec();
    raw.workspace_mut().zeroize();
    output.as_mut().fill(T::MAX);
    raw.encrypt_encoded_crt_to(&encoded, &mut output, &mut StdRng::seed_from_u64(52));
    assert_eq!(output.as_ref(), saved);
    for component in 0..=2 {
        for (limb, (&q, &root)) in values.iter().zip(&roots).enumerate() {
            let expected = if component == 2 {
                direct_transform(
                    &encoded.as_ref()[limb * 32..][..32]
                        .iter()
                        .map(|&value| value.as_into())
                        .collect::<Vec<_>>(),
                    root,
                    q,
                )
            } else {
                vec![0; 32]
            };
            let start = component * size.rns_poly_len() + limb * 32;
            let difference: Vec<u64> = output.as_ref()[start..][..32]
                .iter()
                .zip(&zero.as_ref()[start..][..32])
                .map(|(&left, &right)| {
                    let left: u64 = left.as_into();
                    let right: u64 = right.as_into();
                    (left + q - right) % q
                })
                .collect();
            assert_eq!(
                difference, expected,
                "raw message belongs only in the body, without delta"
            );
        }
    }
    let error: Vec<u64> = phase(output.as_ref(), &secret, &values, &roots)
        .into_iter()
        .zip(encoded.as_ref())
        .enumerate()
        .map(|(i, (value, &message))| {
            let message: u64 = message.as_into();
            (value + values[i / 32] - message) % values[i / 32]
        })
        .collect();
    // Epk*v + e_body - sum(e_mask*s), using exact sampler support rather than a
    // probabilistic assertion about observed samples or successful decryption.
    let bound = 32 + 21 * (1 + secret.iter().map(|value| value.abs()).sum::<i64>());
    for i in 0..32 {
        assert!(centered_crt(error[i], error[32 + i], &values).abs() <= i128::from(bound));
    }

    let product = u128::from(values[0]) * u128::from(values[1]);
    let log_basis = DecompositionBaseLog::new(8);
    let levels = DecompositionLevelCount::new(2);
    let basis = BigUintApproxSignedBasis::new(base.moduli_product(), log_basis, Some(levels));
    let gadget = CrtGlevParameters::try_from_parts(parameters, base, basis).unwrap();
    let gadget_domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let mut encryptor = public.try_bind_gadget(&gadget_domain).unwrap();
    let ones = Residues::new(vec![T::ONE; 2]);
    let zeros = Residues::new(vec![T::ZERO; 2]);
    let mut encrypted = DcrtGgsw::new(vec![T::MAX; gadget.rns_ggsw_len()]);
    let mut encrypted_zero = encrypted.clone();
    encryptor.encrypt_monomial_ggsw_to(&ones, 31, &mut encrypted, &mut StdRng::seed_from_u64(54));
    encryptor.encrypt_monomial_ggsw_to(
        &zeros,
        31,
        &mut encrypted_zero,
        &mut StdRng::seed_from_u64(54),
    );
    let saved = encrypted.as_ref().to_vec();
    encryptor.workspace_mut().zeroize();
    encryptor.encrypt_monomial_ggsw_to(&ones, 31, &mut encrypted, &mut StdRng::seed_from_u64(54));
    assert_eq!(encrypted.as_ref(), saved);
    let modulus_bits = u128::BITS - product.leading_zeros();
    for row in 0..3 {
        for level in 0..2 {
            let start = row * gadget.rns_glev_len() + level * size.rns_glwe_len();
            let mut difference = Vec::with_capacity(size.rns_glwe_len());
            for component in 0..3 {
                for (limb, (&q, &root)) in values.iter().zip(&roots).enumerate() {
                    let weight = pow_mod(2, modulus_bits - 16 + 8 * level as u32, q);
                    let expected: Vec<_> = points(root, q)
                        .into_iter()
                        .map(|point| {
                            if component == row {
                                mul_mod(weight, pow_mod(point, 31, q), q)
                            } else {
                                0
                            }
                        })
                        .collect();
                    for (i, &expected) in expected.iter().enumerate() {
                        let at = start + component * size.rns_poly_len() + limb * 32 + i;
                        let left: u64 = encrypted.as_ref()[at].as_into();
                        let right: u64 = encrypted_zero.as_ref()[at].as_into();
                        let actual = (left + q - right) % q;
                        assert_eq!(
                            actual, expected,
                            "monomial injection must occur in the matching GGSW row/component"
                        );
                        difference.push(actual);
                    }
                }
            }
            let actual_phase = phase(&difference, &secret, &values, &roots);
            for (limb, &q) in values.iter().enumerate() {
                let mut monomial = vec![0; 32];
                monomial[31] = pow_mod(2, modulus_bits - 16 + 8 * level as u32, q);
                let expected = if row == 2 {
                    monomial
                } else {
                    convolution(&monomial, &secret[row * 32..][..32], q)
                        .into_iter()
                        .map(|value| if value == 0 { 0 } else { q - value })
                        .collect()
                };
                assert_eq!(
                    &actual_phase[limb * 32..][..32],
                    expected,
                    "mask rows carry the negative secret term"
                );
            }
        }
    }
}

#[test]
fn public_and_gadget_encryption_match_independent_phase_oracles() {
    check_public::<u32, U32NttTable>([257, 769], [11, 12]);
    check_public::<u64, U64NttTable>(
        [1_125_899_906_826_241, 1_125_899_906_629_633],
        [18_105_782_770_620, 34_361_371_622_355],
    );
}

#[test]
fn prepared_public_and_gadget_calls_reuse_outputs_without_allocating_or_extra_ntts() {
    let moduli = [257u64, 769].map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(2), PolyLength::new(32)), 2);
    let parameters = Arc::new(
        CrtGlweEncryptionParameters::try_with_error_distribution(
            size,
            &base,
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap(),
    );
    let table = DcrtTable::<CountedTable>::new(PolyLength::new(32), &moduli).unwrap();
    let secret = GlweSecretKey::new(vec![1; 64], size.glwe_size(), SecretKeyDistr::SparseTernary);
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let public = DcrtGlwePublicKey::new(
        &key,
        &parameters,
        &base,
        &table,
        &mut StdRng::seed_from_u64(71),
    );
    let domain = DcrtGlweDomain::try_new(&parameters, &base, &table).unwrap();
    let mut raw = public.try_bind_raw(&domain).unwrap();
    let message = CrtPolynomial::new(vec![3; size.rns_poly_len()]);
    let mut output = DcrtGlweCiphertext::new(vec![7; size.rns_glwe_len()]);
    let mut rng = StdRng::seed_from_u64(72);
    let budget = (8, 0); // Two limbs: one ephemeral + three noisy components.
    raw.encrypt_zeros_to(&mut output, &mut rng);
    let (_, allocations, transforms) = observe(|| raw.encrypt_zeros_to(&mut output, &mut rng));
    assert_eq!((allocations, transforms), (0, budget));
    let (_, allocations, transforms) =
        observe(|| raw.encrypt_encoded_crt_to(&message, &mut output, &mut rng));
    assert_eq!((allocations, transforms), (0, budget));
    raw.workspace_mut().zeroize();
    let (_, allocations, transforms) =
        observe(|| raw.encrypt_encoded_crt_to(&message, &mut output, &mut rng));
    assert_eq!((allocations, transforms), (0, budget));
    let basis = BigUintApproxSignedBasis::new(
        base.moduli_product(),
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(2)),
    );
    let gadget = CrtGlevParameters::try_from_parts(parameters, base, basis).unwrap();
    let gadget_domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let mut gadget_encryptor = public.try_bind_gadget(&gadget_domain).unwrap();
    let coeff = Residues::new(vec![1u64; 2]);
    let mut gadget_output = DcrtGgsw::new(vec![7; gadget.rns_ggsw_len()]);
    let (_, allocations, transforms) = observe(|| {
        gadget_encryptor.encrypt_monomial_ggsw_to(&coeff, 31, &mut gadget_output, &mut rng)
    });
    assert_eq!((allocations, transforms), (0, (3 * 2 * budget.0, 0)));
    let (allocated, allocations, transforms) =
        observe(|| gadget_encryptor.encrypt_monomial_ggsw(&coeff, 0, &mut rng));
    assert_eq!((allocations, transforms), (1, (3 * 2 * budget.0, 0)));
    drop(allocated);
}

#[test]
fn public_and_gadget_reject_invalid_inputs_before_sampling_or_writes() {
    let moduli = [257u64, 769].map(BarrettModulus::new);
    let base = RNSBase::new(&moduli).unwrap();
    let size = RnsGlweSize::new(GlweSize::new(GlweDimension::new(1), PolyLength::new(32)), 2);
    let parameters = Arc::new(CrtGlweEncryptionParameters::new(
        size,
        &base,
        SecretKeyDistr::SparseTernary,
        3.2,
    ));
    let table = DcrtTable::<U64NttTable>::new(PolyLength::new(32), &moduli).unwrap();
    let secret = GlweSecretKey::new(vec![1; 32], size.glwe_size(), SecretKeyDistr::SparseTernary);
    let key = DcrtGlweSecretKey::from_coeff_secret_key(&secret, &table);
    let public = DcrtGlwePublicKey::new(
        &key,
        &parameters,
        &base,
        &table,
        &mut StdRng::seed_from_u64(81),
    );
    let domain = DcrtGlweDomain::try_new(&parameters, &base, &table).unwrap();
    let mut raw = public.try_bind_raw(&domain).unwrap();
    for (message_len, output_len) in [
        (size.rns_poly_len() - 1, size.rns_glwe_len()),
        (size.rns_poly_len(), size.rns_glwe_len() + 1),
    ] {
        let message = CrtPolynomial::new(vec![1; message_len]);
        let mut output = DcrtGlweCiphertext::new(vec![7; output_len]);
        let mut rng = StdRng::seed_from_u64(82);
        let mut untouched = StdRng::seed_from_u64(82);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                raw.encrypt_encoded_crt_to(&message, &mut output, &mut rng);
            }))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
    // Workspace access permits explicit erasure and swaps, so foreign geometry
    // must be rejected even when the ephemeral polynomial has the same length.
    let foreign_size =
        RnsGlweSize::new(GlweSize::new(GlweDimension::new(2), PolyLength::new(32)), 2);
    let foreign_parameters =
        CrtGlweEncryptionParameters::new(foreign_size, &base, SecretKeyDistr::SparseTernary, 3.2);
    let foreign_secret = GlweSecretKey::new(
        vec![1; 64],
        foreign_size.glwe_size(),
        SecretKeyDistr::SparseTernary,
    );
    let foreign_key = DcrtGlweSecretKey::from_coeff_secret_key(&foreign_secret, &table);
    let foreign_public = DcrtGlwePublicKey::new(
        &foreign_key,
        &foreign_parameters,
        &base,
        &table,
        &mut StdRng::seed_from_u64(84),
    );
    let foreign_domain = DcrtGlweDomain::try_new(&foreign_parameters, &base, &table).unwrap();
    let mut foreign_raw = foreign_public.try_bind_raw(&foreign_domain).unwrap();
    std::mem::swap(raw.workspace_mut(), foreign_raw.workspace_mut());
    let mut output = DcrtGlweCiphertext::new(vec![7; size.rns_glwe_len()]);
    let mut rng = StdRng::seed_from_u64(85);
    let mut untouched = StdRng::seed_from_u64(85);
    assert!(
        catch_unwind(AssertUnwindSafe(
            || raw.encrypt_zeros_to(&mut output, &mut rng)
        ))
        .is_err()
    );
    assert!(output.as_ref().iter().all(|&value| value == 7));
    assert_eq!(rng.next_u64(), untouched.next_u64());
    std::mem::swap(raw.workspace_mut(), foreign_raw.workspace_mut());
    let basis = BigUintApproxSignedBasis::new(
        base.moduli_product(),
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(2)),
    );
    let gadget = CrtGlevParameters::try_from_parts(parameters, base, basis).unwrap();
    let domain = DcrtGadgetDomain::try_new(&gadget, &table).unwrap();
    let mut encryptor = public.try_bind_gadget(&domain).unwrap();
    for (residue_count, degree, output_len) in [
        (1, 0, gadget.rns_ggsw_len()),
        (2, 32, gadget.rns_ggsw_len()),
        (2, 0, gadget.rns_ggsw_len() + 1),
    ] {
        let coefficients = Residues::new(vec![1; residue_count]);
        let mut output = DcrtGgsw::new(vec![7; output_len]);
        let mut rng = StdRng::seed_from_u64(83);
        let mut untouched = StdRng::seed_from_u64(83);
        assert!(
            catch_unwind(AssertUnwindSafe(|| encryptor.encrypt_monomial_ggsw_to(
                &coefficients,
                degree,
                &mut output,
                &mut rng
            )))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == 7));
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
}
