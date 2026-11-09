//! Complete coefficient projection with selectable trace/scheme-switch fusion.

use crate::{
    NlevParameters, NtruCiphertext, NtruProjectionMethod, NtruSecretKey, NttNgswCiphertext,
    NttNtruExternalProductWorkspace, NttNtruGadgetEncryptWorkspace, NttNtruSchemeSwitchKey,
    NttNtruSecretKey, NttNtruTraceKey,
};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

/// Projects packed coefficients to NTT NGSW using a selected [`NtruProjectionMethod`].
/// Owns ordinary trace and SS keys once, retaining them for NLev/dual outputs.
/// Separate adds no material; fused terminals add 1 or 7 SS-basis branches.
/// Paired trace adds three inverse-permuted keys per intermediate pair (two copied
/// from ordinary trace, one new combined automorphism) and 3 or 7 terminal branches.
/// The terminal identity branch always borrows SS.
///
/// Separate performs ordinary trace then SS: the last automorphism's fresh error
/// is multiplied by f during SS. Fusion removes that propagation step but changes
/// the residual and key errors, so it does not necessarily reduce total noise.
///
/// In a pair, alpha=sigma_(1+2^s), beta=sigma_(1+2^(s+1)) for odd s. The
/// nonidentity branches are alpha, beta, alpha*beta (not an equally spaced R4
/// subgroup). With a=c/4=<g,d>+epsilon and f*K_gamma,j=g_j*gamma(f)+eta_gamma,j,
/// the phase is `(id+alpha+beta+alpha*beta)(f*c)/4
/// + sum_gamma,j gamma(d_j)*eta_gamma,j - sum_gamma gamma(f*epsilon)`.
///
/// For a fused terminal R=2, 4 or 8, gamma_i=sigma_(1+i*2N/R), original rows satisfy
/// `f*K_i,j = g_j*f*gamma_i(f) + eta_i,j`. With `a = R^-1*c = <g,d> + epsilon`
/// and `P = (sum_i gamma_i)/R`, the output phase is
/// `f*P(mu+e) + sum_(i,j) gamma_i(d_j)*eta_i,j - R*f*P(f*epsilon)`,
/// where `f*c = mu+e`. Prepermuting keys preserves this phase exactly, but
/// merging trace layers changes the residual and noise compared with binary
/// fusion or separate trace/SS. Modular division is not integer division.
/// Publishing these secret-dependent messages requires a related-message/KDM
/// assumption; functional correctness does not certify security or failure rate.
///
/// Online conversion allocates nothing. Scratch is 2N for Separate/FusedLastStage,
/// 8N for FusedLastThreeStages, and 5N (even log2(N)) or 8N (odd) for PairedTrace,
/// in addition to projected rows and the external-product workspace.
pub struct NttNtruProjectionKey<T: FheUint> {
    trace: NttNtruTraceKey<T>,
    scheme_switch: NttNtruSchemeSwitchKey<T>,
    material: ProjectionMaterial<T>,
}

/// Only the selected algorithm owns extra rows; lengths are fixed at generation.
/// Paired terminal length is 3 or 7 according to the parity of log2(N).
enum ProjectionMaterial<T> {
    Separate,
    FusedLastStage(Box<[PrepermutedBranch<T>]>),
    FusedLastThreeStages(Box<[PrepermutedBranch<T>]>),
    PairedTrace {
        branches: Box<[PrepermutedBranch<T>]>,
        // Ascending reverse-trace order: alpha, beta, alpha*beta.
        pairs: Box<[[PrepermutedBranch<T>; 3]]>,
    },
}

/// Inverse-permuted rows are not ordinary NLev_f or NGSW_f. Keep the representation
/// private and paired with the forward map that restores its branch's phase.
struct PrepermutedBranch<T> {
    rows: Vec<T>,
    permutation: primus_ntt::NttAutomorphismPermutation,
}

impl<T: FheUint> PrepermutedBranch<T> {
    /// Store gamma^-1(K) with its forward map; the temporary inverse is only used
    /// at construction. Complete rows and N scratch values come from key generation.
    fn new(
        mut rows: Vec<T>,
        degree: usize,
        poly_length: primus_shape::PolyLength,
        scratch: &mut [T],
    ) -> Self {
        let n = poly_length.get();
        let inverse =
            primus_ntt::NttAutomorphismPermutation::new(inverse_degree(degree, 2 * n), poly_length);
        for mut row in primus_poly::NttPolynomialIterMut::new(&mut rows, n) {
            inverse.apply_to(row.as_ref(), scratch);
            row.as_mut().copy_from_slice(scratch);
        }
        Self {
            rows,
            permutation: primus_ntt::NttAutomorphismPermutation::new(degree, poly_length),
        }
    }
}

impl<T: FheUint> NttNtruProjectionKey<T> {
    /// Generates ordinary trace/SS plus only the selected method's extra material.
    /// Trace stages retain their own basis; the fused terminal uses the SS basis.
    ///
    /// # Panics
    /// Panics for mismatched ring/modulus parameters or more output levels than N.
    /// Inherits the generation checks of [`NttNtruTraceKey::generate`] and
    /// [`NttNtruSchemeSwitchKey::generate`].
    ///
    /// # Correctness
    /// Both secrets represent the same f and NTT representation. Every signed
    /// secret coefficient must have magnitude strictly below Q, as required by
    /// [`primus_reduce::EncodeSigned`]; encoding does not perform general modular
    /// reduction. The caller must account for the fused residual and
    /// related-message assumption above.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn generate<M, Table, R>(
        method: NtruProjectionMethod,
        secret: &NtruSecretKey<T>,
        transformed: &NttNtruSecretKey<T>,
        output_basis: &ApproxSignedBasis<T>,
        trace_parameters: &NlevParameters<T, M>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let n = parameters.poly_length().get();
        assert_eq!(secret.poly_length(), n, "projection secret length mismatch");
        let modulus = parameters.encryption_parameters().cipher_modulus();
        assert_eq!(
            trace_parameters.poly_length(),
            parameters.poly_length(),
            "projection ring mismatch"
        );
        assert_eq!(
            trace_parameters.basis().modulus(),
            parameters.basis().modulus(),
            "projection modulus mismatch"
        );
        assert!(
            output_basis.level_count().get() <= n,
            "projection prefix exceeds polynomial length"
        );
        let trace =
            NttNtruTraceKey::generate(secret, transformed, trace_parameters, ntt, rng, workspace);
        let scheme_switch = NttNtruSchemeSwitchKey::generate(
            secret,
            transformed,
            output_basis,
            parameters,
            ntt,
            rng,
            workspace,
        );
        if method == NtruProjectionMethod::Separate {
            return Self {
                trace,
                scheme_switch,
                material: ProjectionMaterial::Separate,
            };
        }
        let terminal_layers = match method {
            NtruProjectionMethod::Separate => 0, // returned above
            NtruProjectionMethod::FusedLastStage => 1,
            NtruProjectionMethod::FusedLastThreeStages => 3,
            NtruProjectionMethod::PairedTrace => {
                if parameters.poly_length().log_n() & 1 == 0 {
                    2
                } else {
                    3
                }
            }
        };
        let mut encoded = zeroize::Zeroizing::new(vec![T::ZERO; n]);
        let mut permuted = zeroize::Zeroizing::new(vec![T::ZERO; n]);
        modulus.encode_signed_slice_to(secret.as_slice(), &mut encoded);
        let radix = 1usize << terminal_layers;
        let branches: Vec<_> = (0..radix - 1)
            .map(|index| {
                let degree = 1 + (index + 1) * (2 * n / radix);
                primus_poly::CoeffAutomorphismPermutation::new(degree, parameters.poly_length())
                    .apply_to(&encoded, &mut permuted, modulus);
                let mut key = NttNgswCiphertext::zero(parameters.nlev_len());
                // NGSW encryption supplies f: the message is gamma(f), not f*gamma(f).
                transformed.encrypt_ngsw_to(
                    &primus_poly::Polynomial(permuted.as_slice()),
                    &mut key,
                    parameters,
                    ntt,
                    rng,
                    workspace,
                );
                PrepermutedBranch::new(
                    key.into_inner(),
                    degree,
                    parameters.poly_length(),
                    &mut permuted,
                )
            })
            .collect();
        let branches = branches.into_boxed_slice();
        let material = match method {
            NtruProjectionMethod::FusedLastStage => ProjectionMaterial::FusedLastStage(branches),
            NtruProjectionMethod::FusedLastThreeStages => {
                ProjectionMaterial::FusedLastThreeStages(branches)
            }
            NtruProjectionMethod::PairedTrace => {
                // Keep original trace keys for NLEV/dual; two keys per pair are reused
                // as ciphertexts, inverse-permuted into the pair's owned representation.
                let pair_count = (parameters.poly_length().log_n() - terminal_layers) / 2;
                let mut pairs = Vec::with_capacity(pair_count as usize);
                for shift in (1..parameters.poly_length().log_n() - terminal_layers).step_by(2) {
                    let degrees = [1 + (1usize << shift), 1 + (1usize << (shift + 1))];
                    // Exponents live modulo 2N; wrapping preserves those low bits.
                    let combined = degrees[0].wrapping_mul(degrees[1]) & (2 * n - 1);
                    let pair = std::array::from_fn(|i| {
                        let degree = if i < 2 { degrees[i] } else { combined };
                        let rows = if i < 2 {
                            trace
                                .automorphism_keys()
                                .iter()
                                .find(|key| key.degree() == degree)
                                .expect("generated binary trace contains each paired degree")
                                .key_switching_rows()
                                .to_vec()
                        } else {
                            primus_poly::CoeffAutomorphismPermutation::new(
                                degree,
                                parameters.poly_length(),
                            )
                            .apply_to(&encoded, &mut permuted, modulus);
                            let mut key =
                                crate::NttNlevCiphertext::zero(trace_parameters.nlev_len());
                            // The trace and SS generators above already validated both domains.
                            transformed.encrypt_nlev_kernel_to(
                                primus_poly::Polynomial(&permuted),
                                key.as_mut_view(),
                                trace_parameters,
                                ntt,
                                rng,
                                workspace,
                            );
                            key.into_inner()
                        };
                        PrepermutedBranch::new(
                            rows,
                            degree,
                            parameters.poly_length(),
                            &mut permuted,
                        )
                    });
                    pairs.push(pair);
                }
                ProjectionMaterial::PairedTrace {
                    branches,
                    pairs: pairs.into_boxed_slice(),
                }
            }
            NtruProjectionMethod::Separate => ProjectionMaterial::Separate,
        };
        Self {
            trace,
            scheme_switch,
            material,
        }
    }

    /// Returns the algorithm bound to this key's material.
    #[must_use]
    pub fn method(&self) -> NtruProjectionMethod {
        match &self.material {
            ProjectionMaterial::Separate => NtruProjectionMethod::Separate,
            ProjectionMaterial::FusedLastStage(_) => NtruProjectionMethod::FusedLastStage,
            ProjectionMaterial::FusedLastThreeStages(_) => {
                NtruProjectionMethod::FusedLastThreeStages
            }
            ProjectionMaterial::PairedTrace { .. } => NtruProjectionMethod::PairedTrace,
        }
    }

    /// Returns the exact scratch element count for [`Self::project_to`]. Ordinary
    /// trace borrows 2N; a pair needs 5N and a terminal needs (branches+1)N.
    /// Sequential operations reuse the same storage.
    #[must_use]
    pub fn scratch_len(&self) -> usize {
        let polynomials = match &self.material {
            ProjectionMaterial::Separate | ProjectionMaterial::FusedLastStage(_) => 2,
            ProjectionMaterial::FusedLastThreeStages(_) => 8,
            ProjectionMaterial::PairedTrace { branches, .. } => (branches.len() + 1).max(5),
        };
        polynomials * self.scheme_switch.poly_length()
    }

    /// Returns the ordinary trace material for coefficient-domain NLev outputs.
    #[must_use]
    pub fn trace_key(&self) -> &NttNtruTraceKey<T> {
        &self.trace
    }

    /// Returns the shared identity-branch key, also usable for ordinary NLev-to-NGSW.
    #[must_use]
    pub fn scheme_switch_key(&self) -> &NttNtruSchemeSwitchKey<T> {
        &self.scheme_switch
    }

    /// Projects the first output-basis coefficients and writes their NTT NGSW.
    /// NLEV-only/dual-output consumers must use the original projection instead.
    ///
    /// # Correctness
    /// Input is in coefficient form with canonical residues under the same f and Q
    /// as the keys. Output uses their bound NTT representation. Output scalars come
    /// from the caller's BR LUT and must match
    /// the output basis. For each coefficient i, its input phase must contain
    /// `g_out,i * m`; the result encrypts m at that gadget level. General message
    /// tails are allowed. In fused blocks decomposition precedes the automorphism: negated balanced
    /// digits can reach +B/2 and are never decomposed again.
    ///
    /// Overwrites every output row. `projected` holds N times the output level
    /// count coefficients; `scratch` has exactly [`Self::scratch_len`] elements.
    /// Both may contain arbitrary initial values and are reused without allocation.
    ///
    /// # Panics
    /// Checks ring/basis/table and exact input/output/projected/scratch
    /// lengths before writes. No online allocation; all borrows are disjoint.
    #[allow(clippy::too_many_arguments)]
    pub fn project_to<M, Table>(
        &self,
        input: NtruCiphertext<&[T]>,
        mut output: NttNgswCiphertext<&mut [T]>,
        projected: &mut [T],
        scratch: &mut [T],
        modulus: M,
        ntt: &Table,
        product: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let ss = &self.scheme_switch;
        let n = ss.poly_length();
        let count = ss.output_basis().level_count().get();
        let output_len = n * count;
        assert_eq!(
            ss.key_basis().modulus(),
            Some(modulus.value()),
            "projection modulus mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "projection table modulus mismatch"
        );
        assert_eq!(
            ntt.poly_length().get(),
            n,
            "projection table length mismatch"
        );
        assert_eq!(
            product.poly_length().get(),
            n,
            "projection workspace length mismatch"
        );
        assert_eq!(input.as_ref().len(), n, "projection input length mismatch");
        assert_eq!(
            projected.len(),
            output_len,
            "projection row storage length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            output_len,
            "projection output length mismatch"
        );
        assert_eq!(
            scratch.len(),
            self.scratch_len(),
            "projection scratch length mismatch"
        );
        match &self.material {
            ProjectionMaterial::Separate => {
                self.project_binary_prefix(input, projected, 0, scratch, modulus, ntt, product);
                self.scheme_switch.apply_to(
                    &crate::NlevCiphertext::new(projected),
                    &mut output,
                    modulus,
                    ntt,
                    product,
                );
            }
            ProjectionMaterial::FusedLastStage(branches) => {
                self.project_binary_prefix(input, projected, 1, scratch, modulus, ntt, product);
                self.terminal_rows_to::<_, _, 1>(
                    branches, projected, output, scratch, modulus, ntt, product,
                );
            }
            ProjectionMaterial::FusedLastThreeStages(branches) => {
                self.project_binary_prefix(input, projected, 3, scratch, modulus, ntt, product);
                self.terminal_rows_to::<_, _, 7>(
                    branches, projected, output, scratch, modulus, ntt, product,
                );
            }
            ProjectionMaterial::PairedTrace { branches, pairs } => {
                // Keep the established pair and row order, including normalization.
                for (i, mut row) in primus_lattice::ntru::NtruIterMut::new(projected, n).enumerate()
                {
                    input.mul_monomial_to((2 * n - i) & (2 * n - 1), &mut row, modulus);
                    for pair in pairs {
                        self.pair_assign(pair, row.as_mut(), scratch, modulus, ntt, product);
                    }
                }
                if branches.len() == 3 {
                    self.terminal_rows_to::<_, _, 3>(
                        branches, projected, output, scratch, modulus, ntt, product,
                    );
                } else {
                    self.terminal_rows_to::<_, _, 7>(
                        branches, projected, output, scratch, modulus, ntt, product,
                    );
                }
            }
        }
    }

    /// Shift each requested coefficient to zero and run the ordinary reverse prefix.
    /// The caller validated every layout; the fused terminal supplies omitted layers.
    #[allow(clippy::too_many_arguments)]
    fn project_binary_prefix<M, Table>(
        &self,
        input: NtruCiphertext<&[T]>,
        projected: &mut [T],
        terminal_layers: usize,
        scratch: &mut [T],
        modulus: M,
        ntt: &Table,
        product: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let n = self.trace.poly_length();
        let levels = self.trace.automorphism_count() - terminal_layers;
        for (i, mut row) in primus_lattice::ntru::NtruIterMut::new(projected, n).enumerate() {
            input.mul_monomial_to((2 * n - i) & (2 * n - 1), &mut row, modulus);
            self.trace.reverse_prefix_assign(
                row.as_mut(),
                levels,
                &mut scratch[..2 * n],
                modulus,
                ntt,
                product,
            );
        }
    }

    /// Normalize each row in Z_Q and run the selected terminal without inner dispatch.
    /// Keys contain gamma^-1(K); the kernel restores gamma after each branch product.
    #[allow(clippy::too_many_arguments)]
    fn terminal_rows_to<M, Table, const K: usize>(
        &self,
        branches: &[PrepermutedBranch<T>],
        projected: &mut [T],
        mut output: NttNgswCiphertext<&mut [T]>,
        scratch: &mut [T],
        modulus: M,
        ntt: &Table,
        product: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let n = self.scheme_switch.poly_length();
        let inverse_two = (modulus.value() >> 1u32) + T::ONE;
        let keys = std::array::from_fn::<_, K, _>(|i| {
            (
                crate::NttNlevCiphertext::new(branches[i].rows.as_slice()),
                &branches[i].permutation,
            )
        });
        let mut rows = crate::NlevCiphertext::new(projected);
        for (mut row, out) in rows.iter_ntru_mut(n).zip(output.iter_ntt_ntru_mut(n)) {
            for _ in 0..(K + 1).ilog2() {
                for value in row.as_mut() {
                    *value = (*value >> 1u32) + (*value & T::ONE) * inverse_two;
                }
            }
            crate::NttNlevCiphertext::external_product_prepermuted_sum_ntt_to(
                Some(crate::NttNlevCiphertext::new(self.scheme_switch.as_slice())),
                keys.clone(), // Borrowed views only; no key rows are cloned.
                row.as_view(),
                out,
                self.scheme_switch.key_basis(),
                modulus,
                ntt,
                &mut scratch[..(K + 1) * n],
                product,
            );
        }
    }
    /// Normalizes c by four in Z_Q and adds its three automorphism products.
    /// Identity is a=c/4 itself, not an identity gadget product. For
    /// a=<g,d>+epsilon, added error is sum gamma(d)*eta - sum gamma(f*epsilon).
    #[allow(clippy::too_many_arguments)]
    fn pair_assign<M, Table>(
        &self,
        pair: &[PrepermutedBranch<T>; 3],
        row: &mut [T],
        scratch: &mut [T],
        modulus: M,
        ntt: &Table,
        product: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let n = row.len();
        let inv2 = (modulus.value() >> 1u32) + T::ONE;
        for _ in 0..2 {
            for x in row.iter_mut() {
                *x = (*x >> 1u32) + (*x & T::ONE) * inv2;
            }
        }
        let (work, out) = scratch[..5 * n].split_at_mut(4 * n);
        crate::NttNlevCiphertext::external_product_prepermuted_sum_ntt_to(
            None,
            pair.each_ref().map(|b| {
                (
                    crate::NttNlevCiphertext::new(b.rows.as_slice()),
                    &b.permutation,
                )
            }),
            NtruCiphertext::new(&*row),
            crate::NttNtruCiphertext::new(&mut *out),
            self.trace.basis(),
            modulus,
            ntt,
            work,
            product,
        );
        ntt.inverse_transform_slice(out);
        modulus.reduce_add_slice_assign(row, out);
    }
}

/// Odd inverse modulo a power of two by Newton doubling; construction only.
fn inverse_degree(degree: usize, twice_n: usize) -> usize {
    let mut inverse = 1usize;
    let mut bits = 1;
    while bits < twice_n.trailing_zeros() {
        inverse = inverse.wrapping_mul(2usize.wrapping_sub(degree.wrapping_mul(inverse)));
        bits *= 2;
    }
    inverse & (twice_n - 1)
}
