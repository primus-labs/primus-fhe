//! DN07 protocol implementation (Damgård-Nielsen 2007) for honest-majority MPC.
//! Provides t-privacy in an (n,t) threshold setting where n > 2t.

use crate::{error::MPCErr, MPCBackend, MPCResult};
use algebra::random::Prg;
use algebra::{Field, U64FieldEval};
use network::netio::{NetIO, Participant};
use network::IO;
use rand::distributions::Uniform;
use rand::prelude::Distribution;
use rand::{RngCore, SeedableRng};
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;

/// MPC backend implementing the DN07 protocol with honest-majority security.
pub struct DNBackend<const P: u64> {
    party_id: u32,
    num_parties: u32,
    num_threshold: u32,
    // Precomputed Lagrange coefficients for interpolation
    lagrange_coeffs: (Vec<u64>, Vec<u64>),
    // Vandermonde matrix for share generation
    van_matrix: Vec<Vec<u64>>,
    // Local PRG for random element generation
    prg: Prg,
    // Shared PRG for consistent randomness across parties
    shared_prg: Prg,
    // Network I/O for communication
    netio: NetIO,
    // Precomputed Beaver triples (a, b, c) where c = a*b
    triple_buffer: VecDeque<(u64, u64, u64)>,
    // Buffer size for triple generation
    triple_buffer_capacity: usize,
    uniform_distr: Uniform<u64>,
}

impl<const P: u64> DNBackend<P> {
    /// Creates a new DN07 backend instance.
    pub fn new(
        party_id: u32,
        num_parties: u32,
        num_threshold: u32,
        triple_required: u32,
        participants: Vec<Participant>,
    ) -> Self {
        // Initialize Vandermonde matrix for share generation
        let party_positions: Vec<u64> = (1..=num_parties as u64).collect();
        let van_matrix = Self::build_vandermonde_matrix(num_parties, &party_positions);

        // Precompute Lagrange coefficients for efficient reconstruction
        let lagrange_coeffs = Self::compute_lagrange_coefficients(num_threshold, &party_positions);

        // Setup network and PRG instances
        let mut prg = Prg::new();
        let mut netio = NetIO::new(party_id, participants).expect("Network initialization failed");
        let shared_prg = Self::setup_shared_prg(party_id, num_parties, &mut prg, &mut netio);

        // Calculate appropriate buffer size (rounded up to next multiple of (n-t))
        let batch_size = (num_parties - num_threshold) as usize;
        let buffer_size = ((triple_required as usize + batch_size - 1) / batch_size) * batch_size;

        // Create and initialize the backend
        let mut backend = Self {
            party_id,
            num_parties,
            num_threshold,
            lagrange_coeffs,
            van_matrix,
            prg,
            shared_prg,
            netio,
            triple_buffer: VecDeque::with_capacity(buffer_size),
            triple_buffer_capacity: buffer_size,
            uniform_distr: Uniform::new(0, P),
        };

        // Generate initial supply of triples
        backend.generate_triples(buffer_size);
        backend
    }

    /// Builds the Vandermonde matrix for polynomial evaluation at party positions.
    fn build_vandermonde_matrix(num_parties: u32, positions: &[u64]) -> Vec<Vec<u64>> {
        let mut matrix = Vec::with_capacity(num_parties as usize);
        // First row: all 1's
        matrix.push(vec![1; num_parties as usize]);
        // Second row: party positions
        matrix.push(positions.to_vec());
        // Remaining rows: pos^i for each position
        for i in 2..(num_parties as usize) {
            matrix.push(
                (0..num_parties as usize)
                    .map(|j| U64FieldEval::<P>::mul(positions[j], matrix[i - 1][j]))
                    .collect(),
            );
        }

        matrix
    }

    /// Calculates Lagrange coefficients for polynomial interpolation.
    fn compute_lagrange_coefficients(
        num_threshold: u32,
        positions: &[u64],
    ) -> (Vec<u64>, Vec<u64>) {
        let calc_coeffs = |degree: usize| -> Vec<u64> {
            (0..=degree)
                .map(|i| {
                    let (num, den) =
                        (0..=degree)
                            .filter(|&j| j != i)
                            .fold((1, 1), |(num, den), j| {
                                (
                                    U64FieldEval::<P>::mul(num, positions[j]),
                                    U64FieldEval::<P>::mul(
                                        den,
                                        U64FieldEval::<P>::sub(positions[j], positions[i]),
                                    ),
                                )
                            });
                    U64FieldEval::<P>::div(num, den)
                })
                .collect()
        };

        (
            calc_coeffs(num_threshold as usize), // t-degree coefficients
            calc_coeffs((num_threshold * 2) as usize), // 2t-degree coefficients
        )
    }

    /// Creates a common PRG seed shared among all parties.
    fn setup_shared_prg(party_id: u32, num_parties: u32, prg: &mut Prg, netio: &mut NetIO) -> Prg {
        if party_id == 0 {
            // Leader generates and distributes seed
            let seed = prg.random_block();
            let seed_bytes: [u8; 16] = seed.into();

            for receiver_id in 1..num_parties {
                netio
                    .send(receiver_id, &seed_bytes)
                    .expect("Seed distribution failed");
            }

            Prg::from_seed(seed)
        } else {
            // Other parties receive the seed
            let mut seed_bytes = [0u8; 16];
            let len = netio
                .recv(0, &mut seed_bytes)
                .expect("Seed reception failed");

            assert_eq!(len, 16, "Invalid PRG seed length");
            Prg::from_seed(seed_bytes.into())
        }
    }

    /// Generates random field elements.
    fn gen_random_field(&mut self, buf: &mut [u64]) {
        // Create mask for rejection sampling
        let field_mask = u64::MAX >> P.leading_zeros();

        // Fill buffer with field elements using rejection sampling
        for value in buf.iter_mut() {
            *value = loop {
                let random_value = self.prg.next_u64() & field_mask;
                if random_value < P {
                    break random_value;
                }
            }
        }
    }

    /// Interpolates a polynomial using Lagrange coefficients.
    fn interpolate_polynomial(&self, shares: &[u64], lagrange_coefs: &[u64]) -> u64 {
        shares
            .iter()
            .zip(lagrange_coefs.iter())
            .fold(0, |acc, (&share, &coef)| {
                U64FieldEval::<P>::add(acc, U64FieldEval::<P>::mul(share, coef))
            })
    }

    /// Creates secret shares using polynomial of specified degree.
    fn generate_shares(&mut self, values: &[u64], degree: usize) -> Vec<Vec<u64>> {
        values
            .iter()
            .map(|&value| {
                // Create polynomial with random coefficients
                let mut coeffs = vec![0u64; degree + 1];
                coeffs[0] = value; // Constant term is the secret
                self.gen_random_field(&mut coeffs[1..=degree]);

                // Evaluate polynomial at each party's point
                (0..self.num_parties as usize)
                    .map(|party_idx| {
                        (1..=degree).fold(value, |sum, j| {
                            U64FieldEval::<P>::add(
                                sum,
                                U64FieldEval::<P>::mul(coeffs[j], self.van_matrix[j][party_idx]),
                            )
                        })
                    })
                    .collect()
            })
            .collect()
    }

    /// Distributes shares from a dealer to all parties.
    fn share_secrets(
        &mut self,
        dealer_id: u32,
        batch_size: usize,
        shares: Option<Vec<Vec<u64>>>,
    ) -> Vec<u64> {
        if self.party_id == dealer_id {
            let all_shares = shares.expect("Dealer must provide shares");

            // Send shares to each party
            for party_idx in 0..self.num_parties {
                if party_idx as u32 == self.party_id {
                    continue;
                }

                let share_buffer: Vec<u8> = all_shares
                    .iter()
                    .flat_map(|share_vec| share_vec[party_idx as usize].to_le_bytes())
                    .collect();

                self.netio
                    .send(party_idx as u32, &share_buffer)
                    .expect("Share distribution failed");
            }

            // Return own shares
            all_shares
                .iter()
                .map(|share_vec| share_vec[self.party_id as usize])
                .collect()
        } else {
            // Receive shares from dealer
            let mut buffer = vec![0u8; batch_size * 8];

            self.netio
                .recv(dealer_id, &mut buffer)
                .expect("Share reception failed");

            buffer
                .chunks_exact(8)
                .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                .collect()
        }
    }

    /// Reconstructs secrets from shares through polynomial interpolation.
    fn open_secrets(
        &mut self,
        reconstructor_id: u32,
        degree: u32,
        shares: &[u64],
        broadcast_result: bool,
    ) -> Option<Vec<u64>> {
        // Select appropriate coefficients
        let lagrange_coef = match degree {
            d if d == self.num_threshold => &self.lagrange_coeffs.0,
            d if d == (self.num_threshold * 2) => &self.lagrange_coeffs.1,
            _ => panic!("Unsupported polynomial degree"),
        };

        let batch_size = shares.len();

        if self.party_id == reconstructor_id {
            // Reconstructor collects shares
            let mut all_shares = vec![vec![0u64; (degree + 1) as usize]; batch_size];

            // Store own shares
            let pos = self.party_id.min(degree);
            for (i, &share) in shares.iter().enumerate() {
                all_shares[i][pos as usize] = share;
            }

            // Collect shares from other parties
            for party_idx in 0..=degree {
                if party_idx == pos {
                    continue;
                }

                let mut batch_buffer = vec![0u8; batch_size * 8];
                self.netio
                    .recv(party_idx, &mut batch_buffer)
                    .expect("Share collection failed");

                for i in 0..batch_size {
                    let share_bytes = &batch_buffer[i * 8..(i + 1) * 8];
                    all_shares[i][party_idx as usize] =
                        u64::from_le_bytes(share_bytes.try_into().unwrap());
                }
            }

            // Interpolate to recover secrets
            let results: Vec<u64> = all_shares
                .iter()
                .map(|shares| self.interpolate_polynomial(shares, lagrange_coef))
                .collect();

            // Broadcast results if needed
            if broadcast_result {
                let result_buffer: Vec<u8> = results
                    .iter()
                    .flat_map(|&result| result.to_le_bytes())
                    .collect();

                for party_idx in 0..self.num_parties {
                    if party_idx != self.party_id {
                        self.netio
                            .send(party_idx, &result_buffer)
                            .expect("Result broadcast failed");
                    }
                }
            }

            // After network operations, flush appropriate connections
            if broadcast_result {
                // Flush all connections
                for party_id in 0..self.num_parties {
                    if party_id != self.party_id {
                        self.netio
                            .flush(party_id)
                            .expect("Failed to flush network buffer");
                    }
                }
            } else if self.party_id != reconstructor_id {
                // Flush only to the reconstructor
                self.netio
                    .flush(reconstructor_id)
                    .expect("Failed to flush network buffer");
            }

            Some(results)
        } else {
            // Determine if this party participates in reconstruction
            let should_send = if reconstructor_id <= degree {
                self.party_id <= degree && self.party_id != reconstructor_id
            } else {
                self.party_id < degree
            };

            // Send shares if participating
            if should_send {
                let share_buffer: Vec<u8> = shares
                    .iter()
                    .flat_map(|&share| share.to_le_bytes())
                    .collect();

                self.netio
                    .send(reconstructor_id, &share_buffer)
                    .expect("Share sending failed");
            }

            // Receive results if they're being broadcast
            if broadcast_result {
                let mut result_buffer = vec![0u8; batch_size * 8];
                self.netio
                    .recv(reconstructor_id, &mut result_buffer)
                    .expect("Result reception failed");

                let results = result_buffer
                    .chunks_exact(8)
                    .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                    .collect();

                // After network operations, flush appropriate connections
                if broadcast_result {
                    // Flush all connections
                    for party_id in 0..self.num_parties {
                        if party_id != self.party_id {
                            self.netio
                                .flush(party_id)
                                .expect("Failed to flush network buffer");
                        }
                    }
                } else if self.party_id != reconstructor_id {
                    // Flush only to the reconstructor
                    self.netio
                        .flush(reconstructor_id)
                        .expect("Failed to flush network buffer");
                }

                Some(results)
            } else {
                None
            }
        }
    }

    /// Replenishes the Beaver triple buffer.
    fn generate_triples(&mut self, count: usize) {
        self.triple_buffer.clear();

        const MAX_BATCH_SIZE: usize = 128;
        let batch_size =
            MAX_BATCH_SIZE.min(count / (self.num_parties - self.num_threshold) as usize);

        while self.triple_buffer.len() < count {
            let current_batch_size = batch_size.min(
                (count - self.triple_buffer.len())
                    / (self.num_parties - self.num_threshold) as usize,
            );

            let new_triples = self.create_beaver_triples_batch(current_batch_size);
            self.triple_buffer.extend(new_triples);
        }
    }

    /// Generates a batch of Beaver triples (a, b, c where c = a*b).
    fn create_beaver_triples_batch(&mut self, batch_size: usize) -> Vec<(u64, u64, u64)> {
        let output_size = batch_size * (self.num_parties - self.num_threshold) as usize;
        let t_degree = self.num_threshold as usize;

        // Generate random a-values with t-degree polynomials
        let mut random_a = vec![0u64; batch_size];
        self.gen_random_field(&mut random_a);
        let all_a_shares = self.collect_party_shares(batch_size, &random_a, t_degree);

        // Generate random b-values with t-degree polynomials
        let mut random_b = vec![0u64; batch_size];
        self.gen_random_field(&mut random_b);
        let all_b_shares = self.collect_party_shares(batch_size, &random_b, t_degree);

        // Generate random masks with both t and 2t degree polynomials
        let mut random_masks = vec![0u64; batch_size];
        self.gen_random_field(&mut random_masks);
        let all_mask_t_shares = self.collect_party_shares(batch_size, &random_masks, t_degree);
        let all_mask_2t_shares = self.collect_party_shares(batch_size, &random_masks, t_degree * 2);

        // Apply Vandermonde combinations to derive final shares
        let a_shares = self.vandermonde_combine(&all_a_shares, batch_size, output_size);
        let b_shares = self.vandermonde_combine(&all_b_shares, batch_size, output_size);
        let mask_t_shares = self.vandermonde_combine(&all_mask_t_shares, batch_size, output_size);
        let mask_2t_shares = self.vandermonde_combine(&all_mask_2t_shares, batch_size, output_size);

        // Compute d = a*b + R (masked products)
        let d_shares: Vec<u64> = a_shares
            .iter()
            .zip(b_shares.iter())
            .zip(mask_2t_shares.iter())
            .map(|((a, b), mask_r2)| {
                U64FieldEval::<P>::add(U64FieldEval::<P>::mul(*a, *b), *mask_r2)
            })
            .collect();

        // Open masked values
        let opened_values = self
            .open_secrets(0, t_degree as u32 * 2, &d_shares, true)
            .expect("Failed to open masked products");

        // Compute final triples: c = d - r
        a_shares
            .iter()
            .zip(b_shares.iter())
            .zip(opened_values.iter().zip(mask_t_shares.iter()))
            .map(|((a, b), (d, mask_r))| (*a, *b, U64FieldEval::<P>::sub(*d, *mask_r)))
            .collect()
    }

    /// Computes linear combinations of shares using Vandermonde coefficients.
    /// Returns vector of shares after applying the Vandermonde matrix.
    fn vandermonde_combine(
        &self,
        shares: &[u64],
        batch_size: usize,
        output_size: usize,
    ) -> Vec<u64> {
        // batch * n -> batch * (n-t)
        let mut result = vec![0u64; output_size];

        for output_idx in 0..output_size {
            let share_idx = output_idx / batch_size;
            let batch_idx = output_idx % batch_size;

            // Compute linear combination for this share
            result[output_idx] = (0..=self.num_threshold as usize).fold(0u64, |acc, j| {
                let seed = shares[j * batch_size + batch_idx];
                let coefficient = self.van_matrix[share_idx][j];
                U64FieldEval::<P>::add(acc, U64FieldEval::<P>::mul(seed, coefficient))
            });
        }

        result
    }

    /// Collects shares of random values from all parties using polynomial of specified degree.
    fn collect_party_shares(
        &mut self,
        batch_size: usize,
        values: &[u64],
        degree: usize,
    ) -> Vec<u64> {
        let mut all_shares = Vec::with_capacity(self.num_parties as usize * batch_size);

        for party_idx in 0..self.num_parties {
            let shares = if party_idx == self.party_id {
                Some(self.generate_shares(values, degree))
            } else {
                None
            };

            let party_shares = self.share_secrets(party_idx, batch_size, shares);
            all_shares.extend(party_shares);
        }

        all_shares
    }

    /// Gets the next available Beaver triple.
    pub fn next_triple(&mut self) -> (u64, u64, u64) {
        if self.triple_buffer.is_empty() {
            self.generate_triples(self.triple_buffer_capacity);
        }

        self.triple_buffer.pop_front().unwrap()
    }
}

static COUNT: AtomicUsize = AtomicUsize::new(0);

/// MPCBackend trait implementation for DN07 protocol.
impl<const P: u64> MPCBackend for DNBackend<P> {
    type Sharing = u64;
    type RandomField = u64;

    fn party_id(&self) -> u32 {
        self.party_id
    }

    fn num_parties(&self) -> u32 {
        self.num_parties
    }

    fn num_threshold(&self) -> u32 {
        self.num_threshold
    }

    fn field_modulus_value(&self) -> u64 {
        P
    }

    fn neg(&mut self, a: Self::Sharing) -> Self::Sharing {
        U64FieldEval::<P>::neg(a)
    }

    fn add(&mut self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing {
        U64FieldEval::<P>::add(a, b)
    }

    fn sub(&mut self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing {
        U64FieldEval::<P>::sub(a, b)
    }

    fn mul_const(&mut self, a: Self::Sharing, b: u64) -> Self::Sharing {
        U64FieldEval::<P>::mul(a, b)
    }

    fn mul(&mut self, a: Self::Sharing, b: Self::Sharing) -> MPCResult<Self::Sharing> {
        let result = self.mul_element_wise(&[a], &[b])?;
        Ok(result[0])
    }

    fn mul_element_wise(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Vec<Self::Sharing>> {
        assert_eq!(a.len(), b.len(), "Input vector lengths must match");
        let batch_size = a.len();

        COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        println!("Count: {}", COUNT.load(std::sync::atomic::Ordering::SeqCst));

        // Get required Beaver triples
        let triples: Vec<(u64, u64, u64)> = (0..batch_size).map(|_| self.next_triple()).collect();

        // Mask inputs: d = a - r, e = b - s
        let masked_values: Vec<u64> = triples
            .iter()
            .enumerate()
            .flat_map(|(i, &(r, s, _))| {
                [
                    U64FieldEval::<P>::sub(a[i], r),
                    U64FieldEval::<P>::sub(b[i], s),
                ]
            })
            .collect();

        // Open masked values
        let opened_values = self
            .open_secrets(0, self.num_threshold, &masked_values, true)
            .ok_or(MPCErr::ProtocolError("Failed to open masked values".into()))?;

        // Compute c = t + d*s + e*r + d*e
        let results = triples
            .iter()
            .enumerate()
            .map(|(i, &(r, s, t))| {
                let d = opened_values[i * 2];
                let e = opened_values[i * 2 + 1];

                U64FieldEval::<P>::add(
                    U64FieldEval::<P>::add(t, U64FieldEval::<P>::mul(d, s)),
                    U64FieldEval::<P>::add(
                        U64FieldEval::<P>::mul(e, r),
                        U64FieldEval::<P>::mul(d, e),
                    ),
                )
            })
            .collect();

        Ok(results)
    }

    fn inner_product(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Self::Sharing> {
        // Batch multiply all elements
        let products = self.mul_element_wise(a, b)?;

        // Sum locally (no communication needed)
        let sum = products
            .into_iter()
            .fold(0, |acc, val| U64FieldEval::<P>::add(acc, val));

        Ok(sum)
    }

    fn inner_product_const(&mut self, a: &[Self::Sharing], b: &[u64]) -> Self::Sharing {
        assert_eq!(a.len(), b.len(), "Input vector lengths must match");

        // Local computation only (no degree increase)
        let sum = a.iter().zip(b.iter()).fold(0, |acc, (&share, &constant)| {
            U64FieldEval::<P>::mul_add(share, constant, acc)
        });

        sum
    }

    fn double(&mut self, a: Self::Sharing) -> Self::Sharing {
        U64FieldEval::<P>::double(a)
    }

    fn input(&mut self, value: Option<u64>, party_id: u32) -> MPCResult<Self::Sharing> {
        if party_id >= self.num_parties {
            return Err(MPCErr::ProtocolError("Invalid party ID".into()));
        }

        println!("Party {} inputting value: {:?}", self.party_id, value);

        // Create shares directly in the Option
        let share_batch = if self.party_id == party_id {
            let val = value.ok_or(MPCErr::ProtocolError(
                "Input party must provide a value".into(),
            ))?;
            Some(self.generate_shares(&[val], self.num_threshold as usize))
        } else {
            None
        };

        // Distribute the shares with explicit batch size of 1
        let shares = self.share_secrets(party_id, 1, share_batch);
        Ok(shares[0])
    }

    fn reveal(&mut self, a: Self::Sharing, party_id: u32) -> MPCResult<Option<u64>> {
        if party_id >= self.num_parties {
            return Err(MPCErr::ProtocolError("Invalid party ID".into()));
        }

        let result = self.open_secrets(party_id, self.num_threshold, &[a], false);

        // Flush connection with the specific party
        if party_id != self.party_id {
            self.netio
                .flush(party_id)
                .expect("Failed to flush network buffer");
        }

        if self.party_id == party_id {
            match result {
                Some(values) => Ok(Some(values[0])),
                None => Err(MPCErr::ProtocolError(
                    "Failed to receive reconstruction".into(),
                )),
            }
        } else {
            Ok(None)
        }
    }

    fn reveal_to_all(&mut self, a: Self::Sharing) -> MPCResult<u64> {
        let result = self
            .open_secrets(0, self.num_threshold, &[a], true)
            .ok_or(MPCErr::ProtocolError("Failed to reveal value".into()))?;

        // Add explicit flush after all communication in reveal_to_all
        for party_id in 0..self.num_parties {
            if party_id != self.party_id {
                self.netio
                    .flush(party_id)
                    .expect("Failed to flush network buffer");
            }
        }

        Ok(result[0])
    }

    fn shared_rand_coin(&mut self) -> Self::RandomField {
        self.shared_prg.next_u64()
    }

    fn shared_rand_field_element(&mut self) -> u64 {
        self.uniform_distr.sample(&mut self.shared_prg)
    }

    fn shared_rand_field_elements(&mut self, destination: &mut [u64]) {
        destination
            .iter_mut()
            .zip(self.uniform_distr.sample_iter(&mut self.shared_prg))
            .for_each(|(des, value)| {
                *des = value;
            });
    }

    fn input_slice(
        &mut self,
        values: Option<&[Self::Sharing]>,
        party_id: u32,
    ) -> MPCResult<Vec<Self::Sharing>> {
        todo!()
    }

    fn input_slice_with_different_party_ids(
        &mut self,
        values: &[Option<Self::Sharing>],
        party_ids: &[u32],
    ) -> MPCResult<Vec<Self::Sharing>> {
        todo!()
    }

    fn reveal_slice(&mut self, a: &[Self::Sharing], party_id: u32) -> MPCResult<Vec<Option<u64>>> {
        todo!()
    }

    fn reveal_slice_to_all(&mut self, a: &[Self::Sharing]) -> MPCResult<Vec<u64>> {
        todo!()
    }
}
