//! Exact native coefficient preparation for Fourier evaluation material.
//! Ordinary Fourier encryption remains unchanged. These keys satisfy exact native
//! row phase equations before any optional ordinary or split FFT conversion;
//! they are not obtained by
//! inverse-transforming an approximate ordinary Fourier key.
use crate::{NlevParameters, NtruError, NtruSecretKey};
use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_integer::AsInto;
use primus_lattice::{nlev::Nlev, ntru::FourierNtruSplitGadget};
use primus_modulus::NativeModulus;
use primus_poly::CoeffAutomorphismPermutation;
use zeroize::Zeroizing;

/// Temporary exact native inverse shared by BR, trace and SS generation.
/// Secret, inverse and recursive multiplication temporaries are erased on drop.
/// No inverse or coefficient key cache enters the evaluation key.
pub struct NativeNtruGadgetGenerator<T: TorusFftValue> {
    secret: Zeroizing<Vec<u64>>,
    inverse: Zeroizing<Vec<u64>>,
    marker: core::marker::PhantomData<T>,
}
impl<T: TorusFftValue> NativeNtruGadgetGenerator<T> {
    /// Computes `f^-1` in `Z/(2^64)[X]/(X^N+1)` without floating point.
    ///
    /// # Correctness
    /// The caller must first accept this secret under its Fourier stability and
    /// sampling policy. Native invertibility alone does not justify that policy.
    /// # Panics
    /// Requires u64 and a supported power-of-two secret length.
    pub fn try_new(secret: &NtruSecretKey<T>) -> Result<Self, NtruError> {
        assert_eq!(T::BITS, 64, "exact native key generation requires u64");
        let n = primus_shape::PolyLength::new(secret.poly_length());
        let f = Zeroizing::new(
            secret
                .as_slice()
                .iter()
                .map(|&x| x.as_into())
                .collect::<Vec<u64>>(),
        );
        if f.iter().fold(0, |p, &x| p ^ (x & 1)) == 0 {
            return Err(NtruError::NonInvertibleSecretKey);
        }
        // In F2[X]/((X+1)^N), f^N=f(1)=1. Successive Frobenius squares
        // produce f^(N-1), the mod-2 inverse. All operations below wrap at 64 bits.
        let mut power = Zeroizing::new(f.iter().map(|x| x & 1).collect::<Vec<_>>());
        let mut inverse = Zeroizing::new(vec![0; n.get()]);
        inverse[0] = 1;
        for _ in 0..n.log_n() {
            inverse = multiply(&inverse, &power);
            for x in inverse.iter_mut() {
                *x &= 1;
            }
            let mut squared = Zeroizing::new(vec![0; n.get()]);
            for (i, &x) in power.iter().enumerate() {
                squared[(2 * i) & (n.get() - 1)] ^= x;
            }
            power = squared;
        }
        // Newton doubles valid low bits: 1 -> 2 -> 4 -> ... -> 64.
        for _ in 0..6 {
            let mut residual = multiply(&f, &inverse);
            for x in residual.iter_mut() {
                *x = x.wrapping_neg();
            }
            residual[0] = residual[0].wrapping_add(2);
            inverse = multiply(&inverse, &residual);
        }
        Ok(Self {
            secret: f,
            inverse,
            marker: core::marker::PhantomData,
        })
    }
    /// Creates `NLEV[bit]` for public lifting or `NGSW[bit]` for ciphertext controls.
    /// `lift` selects the phase g*bit or g*f*bit, respectively.
    /// Inherits [`Self::try_new`]'s accepted-secret contract.
    pub fn encrypt_bit<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &self,
        bit: bool,
        lift: bool,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        low_bits: u32,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> FourierNtruSplitGadget<T> {
        let mut message = Zeroizing::new(vec![T::ZERO; self.secret.len()]);
        if bit {
            message[0] = T::ONE;
        }
        self.encrypt(&message, lift, parameters, low_bits, fft, rng)
    }
    /// Writes exact native coefficient rows of `NLEV[bit]` (`lift = true`) or
    /// `NGSW[bit]` (`lift = false`), without a Fourier round trip.
    ///
    /// Every row draws independent noise. Its exact phase is `g*bit + e` for
    /// NLEV or `g*f*bit + e` for NGSW, modulo `2^64`. Coefficients are native
    /// residues; conversion to an online Fourier representation is the caller's
    /// responsibility.
    ///
    /// # Correctness
    /// Inherits [`Self::try_new`]'s accepted-secret contract. The supplied
    /// parameters must describe the same secret and its intended noise budget.
    ///
    /// # Panics
    /// Panics if the parameter ring length differs from the secret or `output`
    /// does not contain exactly `parameters.nlev_len()` coefficients.
    pub fn encrypt_bit_coeff_to<R: rand::Rng + rand::CryptoRng>(
        &self,
        bit: bool,
        lift: bool,
        mut output: Nlev<&mut [T]>,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        rng: &mut R,
    ) {
        assert_eq!(
            parameters.poly_length().get(),
            self.secret.len(),
            "native gadget generation domain mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.nlev_len(),
            "native gadget output length mismatch"
        );
        let mut message = Zeroizing::new(vec![T::ZERO; self.secret.len()]);
        if bit {
            message[0] = T::ONE;
        }
        self.encrypt_coefficients(&message, lift, output.as_mut(), parameters, rng);
    }
    /// Creates `NLEV[sigma_degree(f)]` for a reverse-trace automorphism.
    /// The input ciphertext is permuted before this product; output is under f.
    pub fn encrypt_automorphism<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &self,
        degree: usize,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        low_bits: u32,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> FourierNtruSplitGadget<T> {
        let message = self.automorphism_message(degree, parameters.poly_length());
        self.encrypt(&message, true, parameters, low_bits, fft, rng)
    }
    /// Creates `NGSW[f]`, whose exact coefficient row phase is g*f^2+e.
    /// Publishing these secret-dependent messages requires the same KDM assumption
    /// as ordinary NTRU scheme switching; exact key generation proves no security.
    pub fn encrypt_scheme_switch<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &self,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        low_bits: u32,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> FourierNtruSplitGadget<T> {
        let message = Zeroizing::new(
            self.secret
                .iter()
                .map(|&x| T::as_from(x))
                .collect::<Vec<_>>(),
        );
        self.encrypt(&message, false, parameters, low_bits, fft, rng)
    }
    /// Creates inverse-permuted split `NGSW[sigma_degree(f)]` for fused projection.
    /// Before permutation, its exact row phase is g*f*sigma_degree(f)+e.
    /// Reuses the SS basis and accepted-secret/KDM contract of
    /// [`Self::encrypt_scheme_switch`]; this is not `NGSW[f*sigma_degree(f)]`.
    /// # Panics
    /// Requires an odd degree below 2N, matching secret/parameter/FFT lengths,
    /// and the native u64 split range required by [`FourierNtruSplitGadget::from_coefficients`].
    #[must_use]
    pub fn encrypt_scheme_switch_automorphism<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &self,
        degree: usize,
        parameters: &NlevParameters<T, NativeModulus<T>>,
        low_bits: u32,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> crate::FourierNtruSplitAutomorphism<T> {
        let message = self.automorphism_message(degree, parameters.poly_length());
        let cross = self.encrypt(&message, false, parameters, low_bits, fft, rng);
        crate::FourierNtruSplitAutomorphism::new(cross, degree, fft.table())
    }
    /// Encode the secret automorphism before exact coefficient encryption.
    fn automorphism_message(
        &self,
        degree: usize,
        n: primus_shape::PolyLength,
    ) -> Zeroizing<Vec<T>> {
        let encoded = Zeroizing::new(
            self.secret
                .iter()
                .map(|&x| T::as_from(x))
                .collect::<Vec<_>>(),
        );
        let mut message = Zeroizing::new(vec![T::ZERO; self.secret.len()]);
        CoeffAutomorphismPermutation::new(degree, n).apply_to(
            &encoded,
            &mut message,
            NativeModulus::new(),
        );
        message
    }
    // Each gadget is generated independently; the BSK is never retained as a full
    // coefficient copy. NLEV multiplies (e+g*m) by the inverse; NGSW adds g*m after.
    fn encrypt<Table: FftTable, R: rand::Rng + rand::CryptoRng>(
        &self,
        message: &[T],
        lift: bool,
        p: &NlevParameters<T, NativeModulus<T>>,
        low_bits: u32,
        fft: &mut FftEngine<'_, Table>,
        rng: &mut R,
    ) -> FourierNtruSplitGadget<T> {
        let n = self.secret.len();
        assert_eq!(p.poly_length().get(), n, "split generation domain mismatch");
        let mut rows = Zeroizing::new(vec![T::ZERO; p.nlev_len()]);
        self.encrypt_coefficients(message, lift, &mut rows, p, rng);
        FourierNtruSplitGadget::from_coefficients(&rows, p.basis(), low_bits, fft)
    }
    /// Shared exact row formula. Owning entry points established complete lengths;
    /// keep the original row/noise order for existing split key generation.
    fn encrypt_coefficients<R: rand::Rng + rand::CryptoRng>(
        &self,
        message: &[T],
        lift: bool,
        rows: &mut [T],
        p: &NlevParameters<T, NativeModulus<T>>,
        rng: &mut R,
    ) {
        let n = self.secret.len();
        let mut noise = Zeroizing::new(vec![T::ZERO; n]);
        for (g, row) in p.basis().scalar_iter().zip(rows.chunks_exact_mut(n)) {
            primus_distr::sample_gaussian_values_to(
                &mut noise,
                p.encryption_parameters().noise_distribution(),
                rng,
            );
            if lift {
                for (v, &m) in noise.iter_mut().zip(message) {
                    *v = v.wrapping_add(g.wrapping_mul(m));
                }
            }
            let encoded = Zeroizing::new(noise.iter().map(|&x| x.as_into()).collect::<Vec<u64>>());
            let product = multiply(&self.inverse, &encoded);
            for ((out, &c), &m) in row.iter_mut().zip(product.iter()).zip(message) {
                *out = T::as_from(c);
                if !lift {
                    *out = out.wrapping_add(g.wrapping_mul(m));
                }
            }
        }
    }
}

// Exact wrapping Karatsuba; no auxiliary-prime range assumption. Used only during
// offline preparation. Zeroizing owns every secret-dependent recursive buffer.
fn convolution(a: &[u64], b: &[u64]) -> Zeroizing<Vec<u64>> {
    let n = a.len();
    let mut out = Zeroizing::new(vec![0u64; 2 * n]);
    if n <= 32 {
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                out[i + j] = out[i + j].wrapping_add(x.wrapping_mul(y));
            }
        }
        return out;
    }
    let h = n / 2;
    let left = convolution(&a[..h], &b[..h]);
    let right = convolution(&a[h..], &b[h..]);
    let sa = Zeroizing::new(
        a[..h]
            .iter()
            .zip(&a[h..])
            .map(|(&x, &y)| x.wrapping_add(y))
            .collect::<Vec<_>>(),
    );
    let sb = Zeroizing::new(
        b[..h]
            .iter()
            .zip(&b[h..])
            .map(|(&x, &y)| x.wrapping_add(y))
            .collect::<Vec<_>>(),
    );
    let middle = convolution(&sa, &sb);
    for i in 0..n {
        out[i] = out[i].wrapping_add(left[i]);
        out[i + n] = out[i + n].wrapping_add(right[i]);
        out[i + h] =
            out[i + h].wrapping_add(middle[i].wrapping_sub(left[i]).wrapping_sub(right[i]));
    }
    out
}
fn multiply(a: &[u64], b: &[u64]) -> Zeroizing<Vec<u64>> {
    let product = convolution(a, b);
    let n = a.len();
    Zeroizing::new(
        (0..n)
            .map(|i| product[i].wrapping_sub(product[i + n]))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independent quadratic oracle also checks negacyclic signs. Nontrivial
    // odd f(1), not a monomial, exercises all Newton steps and recursive products.
    fn school(a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = a.len();
        let mut out = vec![0u64; n];
        for (i, &x) in a.iter().enumerate() {
            for (j, &y) in b.iter().enumerate() {
                let p = x.wrapping_mul(y);
                let k = i + j;
                if k < n {
                    out[k] = out[k].wrapping_add(p)
                } else {
                    out[k - n] = out[k - n].wrapping_sub(p)
                }
            }
        }
        out
    }
    #[test]
    fn exact_inverse_and_native_convolution() {
        let mut f = vec![0i64; 64];
        f[0] = 1;
        f[1] = 2;
        f[17] = -3;
        f[39] = 1;
        let key = NtruSecretKey::<u64>::new(f, crate::SecretKeyDistr::SparseTernary);
        let generator = NativeNtruGadgetGenerator::try_new(&key).unwrap();
        let mut one = vec![0; 64];
        one[0] = 1;
        assert_eq!(school(&generator.secret, &generator.inverse), one);
        let rhs: Vec<_> = (0u64..64)
            .map(|x| u64::MAX.wrapping_sub(x.wrapping_mul(0x123456789)))
            .collect();
        assert_eq!(
            &*multiply(&generator.inverse, &rhs),
            &school(&generator.inverse, &rhs)
        );
        let even = NtruSecretKey::<u64>::new(vec![2; 32], crate::SecretKeyDistr::SparseTernary);
        assert!(matches!(
            NativeNtruGadgetGenerator::try_new(&even),
            Err(NtruError::NonInvertibleSecretKey)
        ));
    }
}
