use itertools::izip;
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{RnsGlweSize, ggsw::DcrtGgsw, glev::DcrtGlev, glwe::DcrtGlwe};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::{RNSBase, Residues};

use crate::parameter::{validate_dcrt_table, validate_glwe_size, validate_moduli};
use crate::{
    CrtGgswParameters, CrtGlevParameters, CrtGlweEncryptionParameters, CrtGlweParameters,
    DcrtGadgetDomain, DcrtGlweSecretKey, RnsDomainError,
};

#[derive(Clone)]
/// A public GLWE encryption key stored in DCRT form.
pub struct DcrtGlwePublicKey<T: FheUint> {
    key: DcrtGlwe<Vec<T>>,
    size: RnsGlweSize,
    moduli: Vec<T>,
}

impl<T: FheUint> DcrtGlwePublicKey<T> {
    /// Replaces the public ciphertext data from bytes, retaining its domain metadata.
    ///
    /// # Correctness
    /// The bytes must encode a public key in this key's ordered basis and NTT representation;
    /// the payload does not contain or validate that metadata.
    #[inline]
    pub fn read_bytes(&mut self, data: &[u8]) {
        self.key.read_bytes(data);
    }

    /// Writes this public key's ciphertext data to `data`, excluding domain metadata.
    #[inline]
    pub fn write_bytes(&self, data: &mut [u8]) {
        self.key.write_bytes(data);
    }

    /// Returns the bytes count of [`DcrtGlwePublicKey<T>`].
    #[inline]
    pub fn byte_count(&self) -> usize {
        self.key.byte_count()
    }

    /// Generates a public key from codec-free sampling state and its ordered Q base.
    /// The zero encryption needs neither a plaintext modulus nor BFV recovery data.
    ///
    /// # Panics
    /// Panics if the parameters/table/key layouts or ordered moduli differ,
    /// before consuming randomness.
    ///
    /// # Correctness
    /// The secret key and table must use the same NTT representation.
    pub fn new<Table, R, M>(
        secret_key: &DcrtGlweSecretKey<T>,
        params: &CrtGlweEncryptionParameters<T>,
        base_q: &RNSBase<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) -> DcrtGlwePublicKey<T>
    where
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
    {
        params
            .validate_base(base_q)
            .expect("public-key sampling parameters and RNS basis are incompatible");
        let size = params.size();
        validate_dcrt_table(size.poly_length(), base_q.moduli(), table)
            .expect("public-key parameters and table are incompatible");
        secret_key
            .validate_parameters(params.size(), base_q.moduli())
            .expect("public-key secret and parameters are incompatible");
        let poly_length = size.poly_length().get();
        let dcrt_glwe_len = size.rns_glwe_len();

        let moduli = base_q.moduli();
        let moduli_value: Vec<T> = moduli.iter().map(|q| q.value()).collect();
        let uniform_distrs = params.cipher_moduli_uniform_distr();

        let mut data: DcrtGlwe<Vec<T>> = DcrtGlwe::zero(dcrt_glwe_len);

        let (a, mut b) = data.a_b_mut(size.rns_poly_len());

        primus_distr::sample_crt_gaussian_values_to(
            b.0,
            poly_length,
            &moduli_value,
            params.noise_distribution(),
            rng,
        );

        table.transform_slice(b.0);

        secret_key.iter_dcrt_poly().zip(a).for_each(|(si, ai)| {
            primus_distr::sample_crt_uniform_values_to(ai.0, poly_length, uniform_distrs, rng);
            b.add_mul_assign(&ai, &si, poly_length, moduli);
        });

        Self {
            key: data,
            size: params.size(),
            moduli: moduli_value,
        }
    }

    /// Binds this public key to ordinary parameters and a matching table.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for an incompatible layout or ordered basis.
    pub fn try_bind<'a, M, Table>(
        &'a self,
        parameters: &'a CrtGlweParameters<T, M>,
        table: &'a DcrtTable<Table>,
    ) -> Result<DcrtGlwePublicKeyContext<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        validate_dcrt_table(parameters.poly_length(), parameters.cipher_moduli(), table)?;
        self.validate_parameters(parameters.size(), parameters.cipher_moduli())?;
        Ok(DcrtGlwePublicKeyContext {
            key: self,
            parameters,
            table,
        })
    }

    /// Binds this public key to a checked monomial GGSW encryption domain.
    ///
    /// # Errors
    /// Returns [`RnsDomainError`] for an incompatible layout or ordered basis.
    pub fn try_bind_gadget<'a, M, Table>(
        &'a self,
        domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
    ) -> Result<DcrtGgswEncryptor<'a, T, M, Table>, RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.validate_parameters(
            domain.size().rns_glwe_size(),
            domain.parameters().cipher_moduli(),
        )?;
        Ok(DcrtGgswEncryptor { key: self, domain })
    }

    /// Checks the public key's owned layout and numerical basis at binding.
    fn validate_parameters<M: FieldContext<T>>(
        &self,
        size: RnsGlweSize,
        moduli: &[M],
    ) -> Result<(), RnsDomainError<T>> {
        validate_glwe_size(size, self.size)?;
        validate_moduli(
            self.moduli.iter().copied(),
            moduli.iter().map(|m| m.value()),
        )
    }

    /// The context has bound key/parameters/table and the entry checked message length.
    /// NTT identity remains a caller contract. Samples one ephemeral polynomial, then each
    /// noisy GLWE component, adding the scaled message only to the body.
    fn encrypt_crt_kernel<R, M, Table>(
        &self,
        message: CrtPolynomial<&[T]>,
        params: &CrtGlweParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) -> DcrtGlwe<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let dimension = params.dimension();
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let dcrt_glwe_len = params.rns_glwe_len();

        let moduli = params.cipher_moduli();

        let mut result = DcrtGlwe::zero(dcrt_glwe_len);
        let mut v = vec![T::ZERO; rns_poly_len];

        primus_distr::sample_crt_sparse_ternary_values_to(
            &mut v,
            poly_length,
            params.cipher_moduli_minus_one(),
            rng,
        );
        table.transform_slice(&mut v);
        let v_dcrt_poly = DcrtPolynomial(v.as_slice());

        result
            .iter_dcrt_poly_mut(rns_poly_len)
            .zip(self.key.iter_dcrt_poly(rns_poly_len))
            .enumerate()
            .for_each(|(i, (mut ai, pk_ai))| {
                primus_distr::sample_crt_gaussian_values_to(
                    ai.0,
                    poly_length,
                    params.cipher_moduli_value(),
                    params.noise_distribution(),
                    rng,
                );

                if i == dimension.get() {
                    CrtPolynomial(&mut *ai.0).add_mul_factor_assign(
                        &message,
                        params.delta_factor_mod_q().as_ref(),
                        poly_length,
                        params.cipher_moduli_value(),
                    );
                }
                table.transform_slice(ai.0);
                ai.add_mul_assign(&v_dcrt_poly, &pk_ai, poly_length, moduli);
            });

        result
    }

    /// Samples each gadget level independently and adds its scaled monomial
    /// to the selected component before transforming that component. The caller
    /// supplies complete row/residue/scratch layouts in the parameter/table order.
    #[allow(clippy::too_many_arguments)]
    fn encrypt_monomial_dcrt_glev_to<R, Table, M>(
        &self,
        index: usize,
        coeff_residues: Residues<&[T]>,
        degree: usize,
        mut dcrt_glev: DcrtGlev<&mut [T]>,
        params: &CrtGlevParameters<T, M>,
        table: &DcrtTable<Table>,
        v: &mut [T],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        Table: NttTable<ValueT = T>,
        M: FieldContext<T>,
    {
        let poly_length = params.poly_length().get();
        let dcrt_poly_len = params.rns_poly_len();
        let dcrt_glwe_len = params.rns_glwe_len();

        let moduli = params.cipher_moduli();

        dcrt_glev
            .iter_dcrt_glwe_mut(dcrt_glwe_len)
            .zip(params.scalar_residue_iter())
            .for_each(|(mut dcrt_glwe, scalar_residues)| {
                primus_distr::sample_crt_sparse_ternary_values_to(
                    v,
                    poly_length,
                    params.cipher_moduli_minus_one(),
                    rng,
                );
                table.transform_slice(v);
                let v_poly = DcrtPolynomial(&*v);

                dcrt_glwe
                    .iter_dcrt_poly_mut(dcrt_poly_len)
                    .zip(self.key.iter_dcrt_poly(dcrt_poly_len))
                    .enumerate()
                    .for_each(|(i, (mut ai, pk_ai))| {
                        primus_distr::sample_crt_gaussian_values_to(
                            ai.0,
                            poly_length,
                            params.cipher_moduli_value(),
                            params.noise_distribution(),
                            rng,
                        );

                        if i == index {
                            izip!(
                                ai.iter_each_modulus_mut(poly_length),
                                coeff_residues.iter(),
                                scalar_residues.iter(),
                                moduli,
                            )
                            .for_each(
                                |(poly, &coeff_residue, &scalar_residue, &modulus)| {
                                    poly[degree] = modulus.reduce_mul_add(
                                        coeff_residue,
                                        scalar_residue,
                                        poly[degree],
                                    );
                                },
                            );
                        }

                        table.transform_slice(ai.0);

                        ai.add_mul_assign(&v_poly, &pk_ai, poly_length, moduli);
                    });
            });
    }

    /// Adds the gadget monomial to one GLWE component per GGSW row, reusing
    /// one ephemeral buffer across rows and levels. The entry checked output/degree;
    /// residues, key and parameters must share the complete ordered RNS domain.
    fn encrypt_monomial_ggsw_kernel_to<R, Table, M>(
        &self,
        coeff_residues: Residues<&[T]>,
        degree: usize,
        mut result: DcrtGgsw<&mut [T]>,
        params: &CrtGgswParameters<T, M>,
        table: &DcrtTable<Table>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        Table: NttTable<ValueT = T>,
        M: FieldContext<T>,
    {
        let rns_poly_len = params.rns_poly_len();
        let dcrt_glev_len = params.rns_glev_len();

        let mut v = vec![T::ZERO; rns_poly_len];

        result
            .iter_dcrt_glev_mut(dcrt_glev_len)
            .enumerate()
            .for_each(|(i, dcrt_glev)| {
                self.encrypt_monomial_dcrt_glev_to(
                    i,
                    coeff_residues,
                    degree,
                    dcrt_glev,
                    params,
                    table,
                    &mut v,
                    rng,
                );
            });
    }
}

/// A public key bound to ordinary parameters and their DCRT table.
///
/// Ciphertexts use the key's secret and table representation. Numerical checks
/// do not prove NTT identity or a public-encryption noise margin.
pub struct DcrtGlwePublicKeyContext<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlwePublicKey<T>,
    parameters: &'a CrtGlweParameters<T, M>,
    table: &'a DcrtTable<Table>,
}

impl<T, M, Table> DcrtGlwePublicKeyContext<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Encrypts one CRT plaintext polynomial into a newly allocated ciphertext.
    ///
    /// Like [`crate::DcrtGlweSecretKeyContext::encrypt_plaintext_crt_to`], this accepts unscaled
    /// plaintext lifts reduced into each `[0, q_i)` in coefficient-domain CRT
    /// layout and applies `floor(Q/t)` scaling. Passing the already-scaled output
    /// of [`crate::BfvRnsCodec::encode_coeffs_to`] would apply the scale twice.
    ///
    /// # Panics
    ///
    /// Panics if the CRT plaintext length differs from the bound parameters'
    /// [`CrtGlweParameters::rns_poly_len`]. This is checked before consuming randomness.
    #[must_use]
    pub fn encrypt_plaintext_crt<R, A>(
        &self,
        message: &CrtPolynomial<A>,
        rng: &mut R,
    ) -> DcrtGlwe<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
    {
        let params = self.parameters;
        let table = self.table;
        let rns_poly_len = params.rns_poly_len();
        assert_eq!(
            message.as_ref().len(),
            rns_poly_len,
            "CRT plaintext length must match the RNS polynomial layout"
        );
        self.key
            .encrypt_crt_kernel(message.as_view(), params, table, rng)
    }
}

/// A public key bound to one checked monomial GGSW encryption domain.
///
/// Construct with [`DcrtGlwePublicKey::try_bind_gadget`] and reuse its parameters,
/// table and key binding across rows and levels.
pub struct DcrtGgswEncryptor<'a, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    key: &'a DcrtGlwePublicKey<T>,
    domain: &'a DcrtGadgetDomain<'a, T, M, Table>,
}

impl<T, M, Table> DcrtGgswEncryptor<'_, T, M, Table>
where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    /// Encrypts `coeff*X^degree` into a DCRT GGSW ciphertext.
    /// `coeff_residues` has one canonical residue per bound modulus.
    ///
    /// # Panics
    /// Panics if `degree` is not below N.
    #[must_use]
    pub fn encrypt_monomial_ggsw<R>(
        &self,
        coeff_residues: &Residues<impl Data<Elem = T>>,
        degree: usize,
        rng: &mut R,
    ) -> DcrtGgsw<Vec<T>>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let params = self.domain.parameters();
        let dcrt_ggsw_len = params.rns_ggsw_len();

        let mut result: DcrtGgsw<Vec<T>> = DcrtGgsw::zero(dcrt_ggsw_len);

        self.encrypt_monomial_ggsw_to(coeff_residues, degree, &mut result, rng);

        result
    }

    /// Encrypts `coeff*X^degree` into a DCRT GGSW ciphertext.
    /// `coeff_residues` has one canonical residue per bound modulus.
    ///
    /// # Panics
    /// Panics if `degree` is not below N.
    pub fn encrypt_monomial_ggsw_to<R, A>(
        &self,
        coeff_residues: &Residues<impl Data<Elem = T>>,
        degree: usize,
        result: &mut DcrtGgsw<A>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        let params = self.domain.parameters();
        let table = self.domain.table();
        debug_assert_eq!(result.as_ref().len(), params.rns_ggsw_len());
        assert!(degree < params.poly_length().get());
        self.key.encrypt_monomial_ggsw_kernel_to(
            coeff_residues.view(),
            degree,
            result.as_mut_view(),
            params,
            table,
            rng,
        );
    }
}
