//! DN07 protocol implementation (Damgård-Nielsen 2007) for honest-majority MPC.
//! Provides t-privacy in an (n,t) threshold setting where n > 2t.
use crate::{error::MPCErr, MPCBackend, MPCResult};
use algebra::ntt::NumberTheoryTransform;
use algebra::random::Prg;
use algebra::reduce::{Reduce, ReduceAdd, ReduceDouble, ReduceNeg, ReduceSub};
use algebra::{modulus::PowOf2Modulus, Field, NttField, U64FieldEval};
use bytemuck::{cast_slice, cast_slice_mut};
use crossbeam::channel;
use network::netio::{NetIO, Participant};
use network::IO;
use rand::distributions::Uniform;
use rand::prelude::*;
use rand::{RngCore, SeedableRng};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
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
    /// Network I/O for communication
    //pub netio: NetIO,
    pub netio: Arc<NetIO>,

    // Precomputed Beaver triples (a, b, c) where c = a*b
    triple_buffer: VecDeque<(u64, u64, u64)>,
    // Buffer size for triple generation
    triple_buffer_capacity: usize,

    // Precomputed double randoms ([r]_t, [t]_{2t})
    doublerandom_buffer: VecDeque<(u64, u64)>,
    // Buffer size for double random generation
    doublerandom_buffer_capacity: usize,

    uniform_distr: Uniform<u64>,
    ntt_table: <U64FieldEval<P> as NttField>::Table,

    // Precomputed Beaver triples (a, b, c) where c = a*b over z2k
    triplez2k_buffer: VecDeque<(u64, u64, u64)>,

    //pre-shared prg seed
    shared_prgs_pair_to_pair: Vec<Arc<Mutex<Prg>>>,

    ////pre-shared prg seed for additive secret sharing
    shared_prgs_pair_to_pair_additive: Vec<Prg>,

    //pre_shamir_to_additive_vec
    reverse_vander_matrix: Vec<Vec<u64>>,

    //pre_shamir_to_additive_vec
    pre_shamir_to_additive_vec: Vec<u64>,

    //count double random times
    total_mul_triple_duration: Duration,

    //count multiplication
    mul_count: u32,

    // count z2k multiplication
    mul_count_z2k: u32,
}

impl<const P: u64> DNBackend<P> {
    /// Creates a new DN07 backend instance.
    pub fn new(
        party_id: u32,
        num_parties: u32,
        num_threshold: u32,
        triple_required: u32,
        participants: Vec<Participant>,
        polynomial_size: usize,
        need_mul_init: bool,
        need_prg_init: bool,
    ) -> Self {
        // Initialize Vandermonde matrix for share generation
        let party_positions: Vec<u64> = (1..=num_parties as u64).collect();
        let van_matrix = Self::build_vandermonde_matrix(num_parties, &party_positions);

        // Precompute Lagrange coefficients for efficient reconstruction
        let lagrange_coeffs = Self::compute_lagrange_coefficients(num_threshold, &party_positions);

        // Setup network and PRG instances
        let mut prg = Prg::new();
        //let mut netio = NetIO::new(party_id, participants).expect("Network initialization failed");
        let netio = Arc::new(
            NetIO::new(party_id, participants).expect("Network initialization failed,party id: {}"),
        );

        let shared_prg =
            Self::setup_shared_prg(party_id, num_parties, &mut prg, Arc::clone(&netio));
        // Calculate appropriate buffer size (rounded up to next multiple of (n-t))
        let batch_size = (num_parties - num_threshold) as usize;
        let buffer_size = (triple_required as usize).div_ceil(batch_size) * batch_size;
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
            shared_prgs_pair_to_pair: Vec::new(),
            shared_prgs_pair_to_pair_additive: Vec::new(),
            triplez2k_buffer: VecDeque::with_capacity(buffer_size),

            reverse_vander_matrix: Vec::with_capacity(num_parties as usize),
            pre_shamir_to_additive_vec: Vec::new(),
            doublerandom_buffer: VecDeque::with_capacity(buffer_size),
            doublerandom_buffer_capacity: buffer_size,

            uniform_distr: Uniform::new(0, P),
            ntt_table: <U64FieldEval<P> as NttField>::generate_ntt_table(
                polynomial_size.trailing_zeros(),
            )
            .unwrap(),
            total_mul_triple_duration: Duration::ZERO,
            mul_count: 0,
            mul_count_z2k: 0,
        };

        // Generate initial supply of triples
        // backend.generate_triples(buffer_size);
        // backend

        // Generate initial supply of triples
        backend.init_shamir_to_additive_vec_z2k();
        if need_prg_init {
            backend.init_pair_to_pair_prg();
            backend.init_pair_to_pair_prg_addiitive();
        }

        if need_mul_init {
            //backend.init_shamir_to_additive_vec_z2k();
            backend.generate_doublerandoms(buffer_size);
        }

        backend
    }

    // /// lock the netio
    // pub fn netio_lock(&self) -> std::sync::MutexGuard<'_, NetIO> {
    //     self.netio.lock().unwrap()
    // }
    fn send_with_retry(
        &self,
        netio: &NetIO,
        pid: u32,
        share_column: &[u8],
        max_retries: usize,
    ) -> Result<(), String> {
        let data = bytemuck::cast_slice(share_column);

        for attempt in 0..=max_retries {
            let send_result = netio.send(pid, data);
            let flush_result = send_result.and_then(|_| netio.flush(pid));

            match flush_result {
                Ok(_) => return Ok(()),
                Err(e) if attempt < max_retries => {
                    eprintln!(
                        "Attempt {} failed: {:?}. Retrying..., party : {} send to {} failed",
                        attempt + 1,
                        e,
                        self.party_id,
                        pid
                    );
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => return Err(format!("Failed after {} attempts: {:?}", attempt + 1, e)),
            }
        }
        unreachable!()
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
                    .map(|j| <U64FieldEval<P>>::mul(positions[j], matrix[i - 1][j]))
                    .collect(),
            );
        }
        matrix
    }

    ///  parallel_recv_from_many
    fn parallel_recv_from_many(
        &self,
        netio: Arc<NetIO>,
        from_ids: &[u32],
        item_count: usize,
    ) -> HashMap<u32, Vec<u64>> {
        let mut results = HashMap::new();
        let mut handles = vec![];

        for &from_id in from_ids {
            let netio_clone = Arc::clone(&netio);

            let handle = thread::spawn(move || {
                let mut buffer = vec![0u64; item_count];
                {
                    netio_clone
                        .recv(from_id, cast_slice_mut(&mut buffer))
                        .expect("Recv failed");
                }
                (from_id, buffer)
            });

            handles.push(handle);
        }
        handles.into_iter().for_each(|handle| {
            let (from_id, buffer) = handle.join().expect("Recv thread panicked");
            results.insert(from_id, buffer);
        });
        results
    }

    /// eval polynomial
    pub fn eval_polynomial(coeffs: &[u64], x: u64) -> u64 {
        let mut res = 0;
        let mut power = 1;
        for &c in coeffs {
            res = <U64FieldEval<P>>::mul_add(c, power, res);
            power = <U64FieldEval<P>>::mul(power, x);
        }
        res
    }

    // streaming version
    fn generate_shares_streaming_and_send(
        &self,
        values: &[u64],
        degree: usize,
        target_range: (u32, u32),
    ) -> Vec<u64> {
        let (start_id, end_id) = target_range;
        let party_id = self.party_id;
        let van_matrix_ref = &self.van_matrix;
        let (tx, rx) = mpsc::channel::<Vec<u64>>();

        let my_shares = std::thread::scope(|s| {
            for pid in start_id..end_id {
                let netio = Arc::clone(&self.netio);
                let tx = tx.clone();
                let my_pid = party_id;
                let mut prg = self.prg.clone();
                s.spawn(move || {
                    // Send incrementally per share (streaming)
                    let mut share_column = vec![0u64; values.len()];
                    let field_mask = u64::MAX >> P.leading_zeros();

                    for (&val, share_ele) in values.iter().zip(share_column.iter_mut()) {
                        let mut coeffs = vec![0u64; degree + 1];
                        coeffs[0] = val;

                        for coeff in coeffs.iter_mut().take(degree + 1).skip(1) {
                            *coeff = loop {
                                let r = prg.next_u64() & field_mask;
                                if r < P {
                                    break r;
                                }
                            };
                        }
                        let share = (1..=degree).fold(coeffs[0], |sum, j| {
                            <U64FieldEval<P>>::mul_add(
                                coeffs[j],
                                van_matrix_ref[j][pid as usize],
                                sum,
                            )
                        });
                        *share_ele = share;
                    }

                    if pid != my_pid {
                        let data = bytemuck::cast_slice(&share_column);
                        //let _ = self.send_with_retry(&netio, self.party_id, data, 1000);
                        netio.send(pid, data).expect("Send failed");
                        netio.flush(pid).expect("Flush failed");
                    } else {
                        tx.send(share_column).expect("Send failed");
                    }
                });
            }

            rx.recv().expect("Receive my_share failed")
            // for h in handles {
            //     h.join().expect("Thread panicked");
            // }
        });
        my_shares
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
                                    <U64FieldEval<P>>::mul(num, positions[j]),
                                    <U64FieldEval<P>>::mul(
                                        den,
                                        <U64FieldEval<P>>::sub(positions[j], positions[i]),
                                    ),
                                )
                            });
                    <U64FieldEval<P>>::div(num, den)
                })
                .collect()
        };

        (
            calc_coeffs(num_threshold as usize), // t-degree coefficients
            calc_coeffs((num_threshold * 2) as usize), // 2t-degree coefficients
        )
    }

    /// Creates a common PRG seed shared among all parties.
    fn setup_shared_prg(party_id: u32, num_parties: u32, prg: &mut Prg, netio: Arc<NetIO>) -> Prg {
        if party_id == 0 {
            // Leader generates and distributes seed
            let seed = prg.random_block();
            let seed_bytes: [u8; 16] = seed.into();

            for receiver_id in 1..num_parties {
                netio
                    .send(receiver_id, &seed_bytes)
                    .expect("Seed distribution failed");
                netio
                    .flush(receiver_id)
                    .expect("Failed to flush network buffer");
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
        <U64FieldEval<P>>::dot_product(shares, lagrange_coefs)
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
                            <U64FieldEval<P>>::mul_add(
                                coeffs[j],
                                self.van_matrix[j][party_idx],
                                sum,
                            )
                        })
                    })
                    .collect()
            })
            .collect()
    }

    /// Creates secret shares using prg.
    fn generate_shares_z2k(&mut self, values: &[u64], degree: usize) -> Vec<Vec<u64>> {
        let num_parties = degree + 1;
        let party_id = self.party_id() as usize;

        let mut shares = Vec::with_capacity(values.len());

        for &val in values.iter() {
            let mut row = vec![0u64; num_parties];
            let mut sum = 0u64;

            for (i, ele) in row.iter_mut().enumerate().take(num_parties) {
                if i != party_id {
                    let rand = self.prg.next_u64();
                    *ele = rand;
                    sum += rand;
                }
            }

            row[party_id] = val - sum;
            shares.push(row);
        }
        shares
    }

    fn share_secrets_parallel(
        &self,
        dealer_id: u32,
        batch_size: usize,
        shares: Option<&Vec<Vec<u64>>>,
        target_range: (u32, u32),
    ) -> Vec<u64> {
        let (start_id, end_id) = target_range;
        let mut my_share_buffer = vec![0u64; batch_size];

        if self.party_id == dealer_id {
            let all_shares_ref = shares.expect("Dealer must provide shares");

            let all_shares = Arc::new(all_shares_ref);

            let mut handles = vec![];

            for party_idx in start_id..end_id {
                if party_idx == self.party_id {
                    continue;
                }

                let share_column: Vec<u64> = (0..batch_size)
                    .map(|i| all_shares[i][party_idx as usize])
                    .collect();

                let netio_clone = Arc::clone(&self.netio);

                handles.push(std::thread::spawn(move || {
                    let data_bytes = cast_slice(&share_column);
                    netio_clone
                        .send(party_idx, data_bytes)
                        .expect("Send failed");
                    netio_clone.flush(party_idx).expect("Flush failed");
                }));
            }

            // wait all threads
            for handle in handles {
                handle.join().expect("Thread panicked");
            }

            // return my share
            for i in 0..batch_size {
                my_share_buffer[i] = all_shares[i][self.party_id as usize];
            }

            my_share_buffer
        } else if self.party_id >= start_id && self.party_id < end_id {
            let mut buffer = vec![0u64; batch_size];
            self.netio
                .recv(dealer_id, cast_slice_mut(&mut buffer))
                .expect("Receive failed");
            buffer
        } else {
            vec![0u64; batch_size]
        }
    }

    fn inverse_vandermonde_mod_p(&mut self, vander: Vec<Vec<u64>>) -> Vec<Vec<u64>> {
        let n = vander.len();
        let mut x = Vec::with_capacity(n);
        for row in vander.iter().take(n) {
            if n > 1 {
                x.push(row[1]);
            } else {
                x.push(0u64);
            }
        }

        let mut inv_l = vec![vec![0u64; n]; n];
        for i in 0..n {
            let mut diag_val = 1u64;
            for m in 0..i {
                let diff = <U64FieldEval<P>>::sub(x[i], x[m]);
                diag_val = <U64FieldEval<P>>::mul(diag_val, diff);
            }

            let inv_diag = if diag_val == 0 {
                panic!("Cannot invert zero in field");
            } else {
                <U64FieldEval<P>>::inv(diag_val)
            };
            inv_l[i][i] = inv_diag;

            for j in 0..i {
                let mut sum = 0u64;
                for (k, row) in inv_l.iter().enumerate().take(i).skip(j) {
                    let l_ik = if k == 0 {
                        1u64
                    } else {
                        let mut prod = 1u64;
                        for m in 0..k {
                            let diff = <U64FieldEval<P>>::sub(x[i], x[m]);
                            prod = <U64FieldEval<P>>::mul(prod, diff);
                        }
                        prod
                    };
                    sum = <U64FieldEval<P>>::add(sum, <U64FieldEval<P>>::mul(l_ik, row[j]));
                }

                let neg_sum = <U64FieldEval<P>>::neg(sum);
                inv_l[i][j] = <U64FieldEval<P>>::mul(inv_diag, neg_sum);
            }
        }

        let mut inv_u = vec![vec![0u64; n]; n];
        for i in 0..n {
            for j in i..n {
                if i == j {
                    inv_u[i][j] = 1;
                } else {
                    let term1 = if i == 0 { 0 } else { inv_u[i - 1][j - 1] };
                    let term2 = <U64FieldEval<P>>::mul(x[j - 1], inv_u[i][j - 1]);
                    inv_u[i][j] = <U64FieldEval<P>>::sub(term1, term2);
                }
            }
        }

        let mut inv_matrix = vec![vec![0u64; n]; n];
        for i in 0..n {
            for j in 0..n {
                let mut sum = 0u64;
                for (k, row) in inv_l.iter().enumerate().take(n) {
                    sum = <U64FieldEval<P>>::mul_add(inv_u[i][k], row[j], sum);
                    // sum = <U64FieldEval<P>>::add(
                    //     sum,
                    //     <U64FieldEval<P>>::mul(inv_u[i][k], inv_l[k][j]),
                    // );
                }
                inv_matrix[i][j] = sum;
            }
        }

        inv_matrix
    }

    /// Distributes shares from a dealer to selected parties with prg.
    fn share_secrets_with_prg(
        &self,
        dealer_id: u32,
        batch_size: usize,
        shares: Option<&Vec<Vec<u64>>>,
        target_range: (u32, u32),
    ) -> Vec<u64> {
        // Default range is all parties
        let (start_id, end_id) = target_range;
        if self.party_id == dealer_id {
            let all_shares = shares.expect("Dealer must provide shares");

            let mut share_buffer = vec![0u64; batch_size];

            // Send shares only to parties in the target range
            for party_idx in start_id..end_id {
                if party_idx == self.party_id {
                    continue;
                }

                share_buffer
                    .iter_mut()
                    .zip(all_shares.iter())
                    .for_each(|(share, share_vec)| {
                        *share = share_vec[party_idx as usize];
                    });

                self.netio
                    .send(party_idx, cast_slice(&share_buffer))
                    .expect("Share distribution failed");
                self.netio
                    .flush(party_idx)
                    .expect("Failed to flush network buffer");
            }

            // Return own shares
            share_buffer
                .iter_mut()
                .zip(all_shares.iter())
                .for_each(|(share, share_vec)| {
                    *share = share_vec[self.party_id as usize];
                });

            share_buffer
        } else if self.party_id >= start_id && self.party_id < end_id {
            // Only receive shares if we're in the target range
            let mut buffer = vec![0u64; batch_size];

            self.netio
                .recv(dealer_id, cast_slice_mut(&mut buffer))
                .expect("Share reception failed");

            buffer
        } else {
            // Not in target range, return prg shares
            let mut my_shares: Vec<u64> = Vec::new();
            for _i in 0..batch_size {
                my_shares.push(
                    self.shared_prgs_pair_to_pair[dealer_id as usize]
                        .lock()
                        .unwrap()
                        .next_u64(),
                );
            }
            my_shares
        }
    }

    /// Distributes shares from a dealer to selected parties.
    fn send_additive_shares_z2k_with_prg(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        sender_id: u32,
    ) -> Vec<u64> {
        // Default range is all parties
        let num_parties = (self.num_threshold + 1) as usize;
        let mut my_shares: Vec<u64> = Vec::new();
        if sender_id == self.party_id {
            let mut shares = Vec::with_capacity(values.unwrap().len());
            for &val in values.unwrap().iter() {
                let mut row = vec![0u64; num_parties];
                let mut sum = 0u64;

                for (i, ele) in row.iter_mut().enumerate().take(num_parties) {
                    if i != sender_id as usize {
                        let rand = self.shared_prgs_pair_to_pair_additive[i].next_u64();
                        *ele = rand;
                        sum += rand;
                    }
                }
                // 当前方负责补足剩余值（值减去其余 share）
                row[sender_id as usize] = val - sum; // 用 wrapping 保证不 panic
                my_shares.push(val - sum);
                shares.push(row);
            }
        } else {
            for _i in 0..batch_size {
                my_shares
                    .push(self.shared_prgs_pair_to_pair_additive[sender_id as usize].next_u64());
            }
        }
        my_shares
    }

    /// open additive secret sharings over z2k
    pub fn open_secrets_z2k(
        &mut self,
        reconstructor_id: u32,
        degree: u32,
        shares: &[u64],
        broadcast_result: bool,
    ) -> Option<Vec<u64>> {
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

            //println!("all shares {:?}", all_shares);

            let results: Vec<u64> = all_shares.iter().map(|row| row.iter().sum()).collect();

            //println!("result: {:?}", results);

            // Broadcast results if needed
            if broadcast_result {
                let result_buffer: Vec<u8> = results
                    .iter()
                    .flat_map(|&result| result.to_le_bytes())
                    .collect();

                for party_idx in 0..=self.num_threshold {
                    if party_idx != self.party_id {
                        self.netio
                            .send(party_idx, &result_buffer)
                            .expect("Result broadcast failed");
                        self.netio
                            .flush(party_idx)
                            .expect("Failed to flush network buffer");
                    }
                }
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
                self.netio
                    .flush(reconstructor_id)
                    .expect("Failed to flush network buffer");
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

                Some(results)
            } else {
                None
            }
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
                        self.netio
                            .flush(party_idx)
                            .expect("Failed to flush network buffer");
                    }
                }
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
                self.netio
                    .flush(reconstructor_id)
                    .expect("Failed to flush network buffer");
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

                Some(results)
            } else {
                None
            }
        }
    }

    fn open_secrets_parallel(
        &mut self,
        reconstructor_id: u32,
        degree: u32,
        shares: &[u64],
        broadcast_result: bool,
    ) -> Option<Vec<u64>> {
        let lagrange_coef = match degree {
            d if d == self.num_threshold => &self.lagrange_coeffs.0,
            d if d == (self.num_threshold * 2) => &self.lagrange_coeffs.1,
            _ => panic!("Unsupported polynomial degree"),
        };

        let batch_size = shares.len();

        if self.party_id == reconstructor_id {
            let mut all_shares = vec![vec![0u64; (degree + 1) as usize]; batch_size];
            let pos = self.party_id.min(degree);

            for (i, &share) in shares.iter().enumerate() {
                all_shares[i][pos as usize] = share;
            }

            let from_ids: Vec<u32> = (0..=degree).filter(|&id| id != pos).collect();

            let recv_map =
                self.parallel_recv_from_many(Arc::clone(&self.netio), &from_ids, batch_size);

            for (&from_id, share_vec) in &recv_map {
                for (i, &val) in share_vec.iter().enumerate() {
                    all_shares[i][from_id as usize] = val;
                }
            }

            let results: Vec<u64> = all_shares
                .iter()
                .map(|shares| self.interpolate_polynomial(shares, lagrange_coef))
                .collect();

            if broadcast_result {
                let result_buffer: Vec<u8> =
                    results.iter().flat_map(|&x| x.to_le_bytes()).collect();

                for party_idx in 0..self.num_parties {
                    if party_idx != self.party_id {
                        self.netio
                            .send(party_idx, &result_buffer)
                            .expect("Broadcast send failed");
                        self.netio.flush(party_idx).expect("Broadcast flush failed");
                    }
                }
            }

            Some(results)
        } else {
            // 非重构方：发送 share / 等待 broadcast
            let should_send = if reconstructor_id <= degree {
                self.party_id <= degree && self.party_id != reconstructor_id
            } else {
                self.party_id < degree
            };

            if should_send {
                let share_buffer: Vec<u8> = shares.iter().flat_map(|&x| x.to_le_bytes()).collect();
                self.netio
                    .send(reconstructor_id, &share_buffer)
                    .expect("Send to reconstructor failed");
                self.netio.flush(reconstructor_id).expect("Flush failed");
            }

            if broadcast_result {
                let mut result_buffer = vec![0u8; batch_size * 8];
                self.netio
                    .recv(reconstructor_id, &mut result_buffer)
                    .expect("Result recv failed");

                let results = result_buffer
                    .chunks_exact(8)
                    .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                    .collect();

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

    /// Replenishes the double random buffer.
    fn generate_doublerandoms(&mut self, count: usize) {
        self.doublerandom_buffer.clear();

        const MAX_BATCH_SIZE: usize = 6000;

        // n = 5, t=2, n-t=3, count=3000, count/(n-t)=1000
        // batch_size = 1000
        //current_batch_size = min(1000, (3000-0)/(3)) = 0
        let batch_size =
            MAX_BATCH_SIZE.min(count / (self.num_parties - self.num_threshold) as usize);

        while self.doublerandom_buffer.len() < count {
            let current_batch_size = batch_size.min(
                (count - self.doublerandom_buffer.len())
                    / (self.num_parties - self.num_threshold) as usize,
            );
            let new_doublerandoms = self.create_double_randoms_batch(current_batch_size);
            self.doublerandom_buffer.extend(new_doublerandoms);
        }
    }

    /// Generates a batch of Beaver triples (a, b, c where c = a*b).
    fn create_beaver_triples_batch(&mut self, batch_size: usize) -> Vec<(u64, u64, u64)> {
        let output_size = batch_size * (self.num_parties - self.num_threshold) as usize;
        let t_degree = self.num_threshold as usize;

        // Generate random a-values with t-degree polynomials
        let mut random_a = vec![0u64; batch_size];
        self.gen_random_field(&mut random_a);
        let all_a_shares = self.collect_party_shares(
            &vec![batch_size; self.num_parties as usize],
            &random_a,
            t_degree,
        );

        // Generate random b-values with t-degree polynomials
        let mut random_b = vec![0u64; batch_size];
        self.gen_random_field(&mut random_b);
        let all_b_shares = self.collect_party_shares(
            &vec![batch_size; self.num_parties as usize],
            &random_b,
            t_degree,
        );

        // Generate random masks with both t and 2t degree polynomials
        let mut random_masks = vec![0u64; batch_size];
        self.gen_random_field(&mut random_masks);
        let all_mask_t_shares = self.collect_party_shares(
            &vec![batch_size; self.num_parties as usize],
            &random_masks,
            t_degree,
        );
        let all_mask_2t_shares = self.collect_party_shares(
            &vec![batch_size; self.num_parties as usize],
            &random_masks,
            t_degree * 2,
        );

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
                <U64FieldEval<P>>::add(<U64FieldEval<P>>::mul(*a, *b), *mask_r2)
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
            .map(|((a, b), (d, mask_r))| (*a, *b, <U64FieldEval<P>>::sub(*d, *mask_r)))
            .collect()
    }

    /// Generates a batch of double randoms ([r]_t, [r]_{2t}).
    fn create_double_randoms_batch(&mut self, batch_size: usize) -> Vec<(u64, u64)> {
        let start = Instant::now();
        let output_size = batch_size * (self.num_parties - self.num_threshold) as usize;
        let t_degree = self.num_threshold as usize;

        let mut random_masks = vec![0u64; batch_size];
        self.gen_random_field(&mut random_masks);

        let all_mask_t_shares = self.collect_party_shares(
            &vec![batch_size; self.num_parties as usize],
            &random_masks,
            t_degree,
        );

        let all_mask_2t_shares = self.collect_party_shares(
            &vec![batch_size; self.num_parties as usize],
            &random_masks,
            t_degree * 2,
        );

        let mask_t_shares = self.vandermonde_combine(&all_mask_t_shares, batch_size, output_size);
        let mask_2t_shares = self.vandermonde_combine(&all_mask_2t_shares, batch_size, output_size);

        let ret: Vec<(u64, u64)> = mask_t_shares
            .iter()
            .cloned()
            .zip(mask_2t_shares.iter().cloned())
            .collect();

        self.total_mul_triple_duration += start.elapsed();

        ret
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

        for (output_idx, item) in result.iter_mut().enumerate() {
            let share_idx = output_idx / batch_size;
            let batch_idx = output_idx % batch_size;

            // Compute linear combination for this share
            *item = (0..=self.num_threshold as usize).fold(0u64, |acc, j| {
                let seed = shares[j * batch_size + batch_idx];
                let coefficient = self.van_matrix[share_idx][j];
                <U64FieldEval<P>>::mul_add(seed, coefficient, acc)
            });
        }

        result
    }

    /// Collects shares of random values from all parties using polynomial of specified degree.
    /// Optimized to require only O(1) communication rounds.
    fn collect_party_shares(&mut self, size: &[usize], values: &[u64], degree: usize) -> Vec<u64> {
        let mut all_shares = Vec::with_capacity(size.iter().sum());

        // Generate our shares
        let our_shares = self.generate_shares(values, degree);

        // Share with higher party IDs
        for party_idx in 0..self.num_parties {
            let shares = (party_idx == self.party_id).then_some(&our_shares);
            let party_shares = self.share_secrets_parallel(
                party_idx,
                size[party_idx as usize],
                shares,
                (party_idx, self.num_parties),
            );
            if party_idx <= self.party_id {
                all_shares.extend_from_slice(&party_shares);
            }
        }

        // Share with lower party IDs
        for party_idx in 0..self.num_parties {
            let shares = (party_idx == self.party_id).then_some(&our_shares);
            let party_shares = self.share_secrets_parallel(
                party_idx,
                size[party_idx as usize],
                shares,
                (0, party_idx),
            );
            if party_idx > self.party_id {
                all_shares.extend_from_slice(&party_shares);
            }
        }

        // for party_idx in 0..self.num_parties {
        //     let shares = (party_idx == self.party_id).then_some(&our_shares);
        //     let party_shares = self.share_secrets_parallel(
        //         party_idx,
        //         size[party_idx as usize],
        //         shares,
        //         (0, self.num_parties),
        //     );
        //     all_shares.extend_from_slice(&party_shares);
        // }
        all_shares
    }

    /// Gets the next available Beaver triple.
    pub fn next_triple(&mut self) -> (u64, u64, u64) {
        if self.triple_buffer.is_empty() {
            self.generate_triples(self.triple_buffer_capacity);
        }

        self.triple_buffer.pop_front().unwrap()
    }

    /// Gets the next available double random.
    pub fn next_doublerandom(&mut self) -> (u64, u64) {
        if self.doublerandom_buffer.is_empty() {
            self.generate_doublerandoms(self.doublerandom_buffer_capacity);
        }

        self.doublerandom_buffer.pop_front().unwrap()
    }

    /// read z2k beaver triples from files
    pub fn read_z2k_triples_from_files(&mut self, filename: &Path) {
        //println!("read file {:?}", filename);
        use std::fs;
        use std::str::FromStr;
        //println!("read file: {:?}", filename);
        let content = fs::read_to_string(filename).expect("Failed to read file");

        for line in content.lines() {
            let parts: Vec<&str> = line.split(", ").collect();
            let values: Vec<u64> = parts
                .iter()
                .filter_map(|p| p.split(": ").nth(1))
                .filter_map(|v| u128::from_str(v).ok())
                .map(|num| num as u64)
                .collect();
            if values.len() == 3 {
                self.triplez2k_buffer
                    .push_back((values[0], values[1], values[2]));
            }
        }
        //println!("z2k triples: {}", self.triplez2k_buffer.len());
    }

    /// next z2k triple
    pub fn next_triple_z2k(&mut self) -> (u64, u64, u64) {
        if self.triplez2k_buffer.is_empty() {
            println!("Triples over tiples finished");
            self.init_z2k_triples_from_files();
        }
        self.triplez2k_buffer.pop_front().unwrap()
    }

    /// Reconstructs secrets from shares through additive
    pub fn open_secrets_z2k_parallel(
        &mut self,
        reconstructor_id: u32,
        degree: u32,
        shares: &[u64],
        broadcast_result: bool,
    ) -> Option<Vec<u64>> {
        let batch_size = shares.len();

        if self.party_id == reconstructor_id {
            // Reconstructor collects shares
            let mut all_shares = vec![vec![0u64; (degree + 1) as usize]; batch_size];
            let from_ids: Vec<u32> = (0..=degree).filter(|&id| id != self.party_id).collect();
            let recv_map =
                self.parallel_recv_from_many(Arc::clone(&self.netio), &from_ids, batch_size);

            // Store own shares
            let pos = self.party_id.min(degree);
            for (i, &share) in shares.iter().enumerate() {
                all_shares[i][pos as usize] = share;
            }

            // Collect shares from other parties
            for (&from_id, share_vec) in &recv_map {
                for (i, &val) in share_vec.iter().enumerate() {
                    all_shares[i][from_id as usize] = val;
                }
            }

            //println!("all shares {:?}", all_shares);

            let results: Vec<u64> = all_shares.iter().map(|row| row.iter().sum()).collect();

            //println!("result: {:?}", results);

            // Broadcast results if needed
            if broadcast_result {
                let result_buffer: Vec<u8> = results
                    .iter()
                    .flat_map(|&result| result.to_le_bytes())
                    .collect();

                for party_idx in 0..=self.num_threshold {
                    if party_idx != self.party_id {
                        self.netio
                            .send(party_idx, &result_buffer)
                            .expect("Result broadcast failed");
                        self.netio
                            .flush(party_idx)
                            .expect("Failed to flush network buffer");
                    }
                }
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
                self.netio
                    .flush(reconstructor_id)
                    .expect("Failed to flush network buffer");
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

                Some(results)
            } else {
                None
            }
        }
    }

    fn init_pair_to_pair_prg(&mut self) {
        for id in (self.party_id + 1..self.num_parties).rev() {
            // Leader generates and distributes seed
            // println!("my party_id:{}, number_parties:{},",self.party_id, self.num_parties);
            let seed = self.prg.random_block();
            let seed_bytes: [u8; 16] = seed.into();
            self.netio
                .send(id, &seed_bytes)
                .expect("Seed distribution failed");
            self.netio
                .flush(id)
                .expect("Failed to flush network buffer");
            self.shared_prgs_pair_to_pair
                .push(Arc::new(Mutex::new(Prg::from_seed(seed))));
        }
        // push my seed
        let seed = self.prg.random_block();
        let seed_bytes: [u8; 16] = seed.into();
        self.shared_prgs_pair_to_pair
            .push(Arc::new(Mutex::new(Prg::from_seed(seed_bytes.into()))));
        //println!("shared pair to pair prg success, {}", self.shared_prgs_pair_to_pair.len());

        for id in (0..self.party_id).rev() {
            // receiver prg seed from party<my_party_id
            let mut seed_bytes = [0u8; 16];
            let len = self
                .netio
                .recv(id, &mut seed_bytes)
                .expect("Seed reception failed");
            assert_eq!(len, 16, "Invalid PRG seed length");
            self.shared_prgs_pair_to_pair
                .push(Arc::new(Mutex::new(Prg::from_seed(seed_bytes.into()))));
        }

        self.shared_prgs_pair_to_pair.reverse();
    }

    fn init_pair_to_pair_prg_addiitive(&mut self) {
        for id in (self.party_id + 1..self.num_parties).rev() {
            // Leader generates and distributes seed
            // println!("my party_id:{}, number_parties:{},",self.party_id, self.num_parties);
            let seed = self.prg.random_block();
            let seed_bytes: [u8; 16] = seed.into();
            self.netio
                .send(id, &seed_bytes)
                .expect("Seed distribution failed");
            self.netio
                .flush(id)
                .expect("Failed to flush network buffer");
            self.shared_prgs_pair_to_pair_additive
                .push(Prg::from_seed(seed));
        }
        // push my seed
        let seed = self.prg.random_block();
        let seed_bytes: [u8; 16] = seed.into();
        self.shared_prgs_pair_to_pair_additive
            .push(Prg::from_seed(seed_bytes.into()));
        //println!("shared pair to pair prg success, {}", self.shared_prgs_pair_to_pair.len());

        for id in (0..self.party_id).rev() {
            // receiver prg seed from party<my_party_id
            let mut seed_bytes = [0u8; 16];
            let len = self
                .netio
                .recv(id, &mut seed_bytes)
                .expect("Seed reception failed");
            assert_eq!(len, 16, "Invalid PRG seed length");
            self.shared_prgs_pair_to_pair_additive
                .push(Prg::from_seed(seed_bytes.into()));
        }

        self.shared_prgs_pair_to_pair_additive.reverse();
    }

    fn init_shamir_to_additive_vec_z2k(&mut self) {
        let num = (self.num_threshold + 1) as usize;
        let mut matrix = Vec::with_capacity(num);

        // 第 0 行：[1, 0, 0, ..., 0]
        let mut first_row = vec![0u64; num];
        first_row[0] = 1;
        matrix.push(first_row);

        // 从 i = 1 到 t: 构建每一行为 x^0, x^1, ..., x^t

        for x in 1..num as u64 {
            let mut temp = 1u64;
            let mut row = Vec::with_capacity(num);
            for _ in 0..num {
                row.push(temp);
                temp = <U64FieldEval<P>>::mul(temp, x); // 累乘 x
            }
            matrix.push(row);
        }

        //println!("self.van_martix:{:?}", self.van_matrix);
        //println!("matrix: {:?} ",matrix);
        self.reverse_vander_matrix = self.inverse_vandermonde_mod_p(matrix);
        //println!("reverse_vander_matrix: {:?}",self.reverse_vander_matrix);

        //println!("van martix:{:?}", self.van_matrix);

        let msize = (self.num_threshold + 1) as usize;

        let mut van_t: Vec<Vec<u64>> = vec![vec![0; msize]; msize];
        for (i, row) in van_t.iter_mut().enumerate() {
            for (j, ele) in row.iter_mut().enumerate() {
                *ele = self.van_matrix[j][i];
            }
        }

        //println!("van_t: {:?} ",van_t);
        for x in self.inverse_vandermonde_mod_p(van_t)[0].iter() {
            self.pre_shamir_to_additive_vec.push(*x);
        }
    }

    // input values, generates shares where P_0 to P_{t}'s shares are generated by prg and do not require send
    fn generate_shares_with_prg(&self, values: &[u64], degree: usize) -> Vec<Vec<u64>> {
        let result: Vec<Vec<u64>> = values
            .iter()
            .map(|&value| {
                let mut fpoint: Vec<u64> = Vec::with_capacity(self.num_threshold as usize + 1);
                fpoint.push(value); // f(0)
                fpoint.extend(
                    (0..degree)
                        .map(|j| self.shared_prgs_pair_to_pair[j].lock().unwrap().next_u64()),
                );

                let coeff: Vec<u64> = self
                    .reverse_vander_matrix
                    .iter()
                    .map(|row| <U64FieldEval<P>>::dot_product(&fpoint, row))
                    .collect();
                let extra_shares: Vec<u64> = ((self.num_threshold as usize)
                    ..(self.num_parties as usize))
                    .map(|party_idx| {
                        (0..=degree).fold(0, |sum, j| {
                            <U64FieldEval<P>>::mul_add(coeff[j], self.van_matrix[j][party_idx], sum)
                        })
                    })
                    .collect();
                fpoint[1..]
                    .iter()
                    .chain(extra_shares.iter())
                    .cloned()
                    .collect()
            })
            .collect();
        result
    }

    fn receive_share_column(&self, dealer_id: u32, batch_size: usize) -> Vec<u64> {
        //println!("Party {} receiving from {}", self.party_id, dealer_id);
        let mut buffer = vec![0u64; batch_size];
        match self
            .netio
            .recv(dealer_id, bytemuck::cast_slice_mut(&mut buffer))
        {
            Ok(_) => (),
            Err(e) => {
                panic!("Failed to receive shares from party {}:{:?}", dealer_id, e);
            }
        }

        buffer
    }

    /// generates shares and sends to all parties
    fn all_parties_generate_shares_and_sends_to_all_parties(
        &mut self,
        values: &[u64],
        batch_size: usize,
        degree: usize,
    ) -> Vec<u64> {
        let shares = self.generate_shares(values, degree);
        let shares_clone = Arc::new(shares);
        let self_ref = &*self;
        let my_id = self_ref.party_id;
        let num_parties = self_ref.num_parties;

        let results = std::thread::scope(|s| {
            let mut handles = Vec::new();
            for i in 0..self_ref.num_parties {
                let shares_clone = Arc::clone(&shares_clone);
                let handle = s.spawn(move || {
                    if i == my_id {
                        self_ref.share_secrets_parallel(
                            i,
                            batch_size,
                            Some(&shares_clone),
                            (0, num_parties),
                        )
                    } else {
                        self_ref.receive_share_column(i, batch_size)
                    }
                });
                handles.push(handle);
            }
            // Wait for all threads to finish and collect results
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap().into_iter())
                .collect::<Vec<u64>>()
        });

        results
    }
}

/// MPCBackend trait implementation for DN07 protocol.
impl<const P: u64> MPCBackend for DNBackend<P> {
    type Sharing = u64;

    type Modulus = <U64FieldEval<P> as Field>::Modulus;

    fn party_id(&self) -> u32 {
        self.party_id
    }

    fn num_parties(&self) -> u32 {
        self.num_parties
    }

    fn num_threshold(&self) -> u32 {
        self.num_threshold
    }

    fn modulus(&self) -> Self::Modulus {
        <U64FieldEval<P>>::MODULUS
    }

    fn field_modulus_value(&self) -> u64 {
        P
    }

    fn neg(&self, a: Self::Sharing) -> Self::Sharing {
        <U64FieldEval<P>>::neg(a)
    }

    fn add(&self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing {
        <U64FieldEval<P>>::add(a, b)
    }

    /// return additive secret sharing of a-b where a is const and b is additive sharing over F_p
    fn sub_additive_const_p(&mut self, a: u64, b: u64) -> u64 {
        if self.party_id() == 0 {
            <U64FieldEval<P>>::sub(a, b)
        } else {
            <U64FieldEval<P>>::neg(b)
        }
    }

    fn mul_additive_const_p(&mut self, a: u64, b: u64) -> u64 {
        <U64FieldEval<P>>::mul(a, b)
    }

    fn inner_product_additive_const_p(&mut self, a: &[u64], b: &[u64]) -> u64 {
        <U64FieldEval<P>>::dot_product(a, b)
    }

    /// return additive secret sharing of a-b where a is const and b is additive sharing
    fn sub_z2k_const(&mut self, a: u64, b: u64, k: u32) -> u64 {
        if self.party_id() == 0 {
            if k < 64 {
                let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
                m_mod.reduce_sub(a, b)
            } else {
                a.wrapping_sub(b)
            }
        } else {
            if k < 64 {
                let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
                m_mod.reduce_neg(b)
            } else {
                b.wrapping_neg()
            }
        }
    }

    /// return additive secret sharing of a-b where a is additive sharing and b is const
    fn sub_z2k_const_a_sub_c(&mut self, a: u64, b: u64, k: u32) -> u64 {
        if self.party_id() == 0 {
            if k < 64 {
                let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
                m_mod.reduce_sub(a, b)
            } else {
                a.wrapping_sub(b)
            }
        } else {
            a
        }
    }

    /// return additive secret sharing of a+b where a is const and b is additive sharing
    fn add_z2k_const(&mut self, a: u64, b: u64, k: u32) -> u64 {
        if self.party_id() == 0 {
            if k < 64 {
                let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
                m_mod.reduce_add(a, b)
            } else {
                a.wrapping_add(b)
            }
        } else {
            b
        }
    }

    /// count times
    fn total_mul_triple_duration(&mut self) -> Duration {
        self.total_mul_triple_duration
    }

    fn add_z2k_slice(&self, a: &[u64], b: &[u64], k: u32) -> Vec<u64> {
        assert_eq!(a.len(), b.len(), "vectors must be of the same length");
        if k < 64 {
            let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
            a.iter()
                .zip(b.iter())
                .map(|(&x, &y)| m_mod.reduce_add(x, y))
                .collect()
        } else {
            a.iter()
                .zip(b.iter())
                .map(|(x, &y)| x.wrapping_add(y))
                .collect()
        }
    }

    fn sub_z2k_slice(&self, a: &[u64], b: &[u64], k: u32) -> Vec<u64> {
        assert_eq!(a.len(), b.len(), "vectors must be of the same length");
        if k < 64 {
            let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
            a.iter()
                .zip(b.iter())
                .map(|(&x, &y)| m_mod.reduce_sub(x, y))
                .collect()
        } else {
            a.iter()
                .zip(b.iter())
                .map(|(x, &y)| x.wrapping_sub(y))
                .collect()
        }
    }

    fn double_z2k_slice(&self, a: &[u64], k: u32) -> Vec<u64> {
        if k < 64 {
            let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
            a.iter().map(|&x| m_mod.reduce_double(x)).collect()
        } else {
            a.iter().map(|x| x.wrapping_shl(1)).collect()
        }
    }

    fn double(&self, a: Self::Sharing) -> Self::Sharing {
        <U64FieldEval<P>>::double(a)
    }

    fn add_const(&self, a: Self::Sharing, b: u64) -> Self::Sharing {
        <U64FieldEval<P>>::add(a, b)
    }

    fn add_const_pub(a: Self::Sharing, b: u64) -> Self::Sharing {
        <U64FieldEval<P>>::add(a, b)
    }

    fn sub(&self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing {
        <U64FieldEval<P>>::sub(a, b)
    }

    fn mul_const(&self, a: Self::Sharing, b: u64) -> Self::Sharing {
        <U64FieldEval<P>>::mul(a, b)
    }

    fn mul_local(&self, a: Self::Sharing, b: Self::Sharing) -> Self::Sharing {
        <U64FieldEval<P>>::mul(a, b)
    }

    fn mul(&mut self, a: Self::Sharing, b: Self::Sharing) -> MPCResult<Self::Sharing> {
        let result = self.mul_element_wise(&[a], &[b])?;
        Ok(result[0])
    }

    fn mul_element_wise_z2k(&mut self, a: &[u64], b: &[u64], k: u32) -> Vec<u64> {
        self.mul_count_z2k = self.mul_count_z2k + a.len() as u32;
        println!("mul count z2k: {}", self.mul_count_z2k);
        assert_eq!(a.len(), b.len(), "Input vector lengths must match");
        let batch_size = a.len();

        // Get required Beaver triples
        let triples: Vec<(u64, u64, u64)> =
            (0..batch_size).map(|_| self.next_triple_z2k()).collect();
        //println!("triples:{:?} ", triples );

        // Mask inputs: d = a - r, e = b - s
        let masked_values: Vec<u64> = triples
            .iter()
            .enumerate()
            .flat_map(|(i, &(r, s, _))| [a[i] - r, b[i] - s])
            .collect();
        //println!("masked values:{:?}", masked_values);
        // Open masked values
        let opened_values = self
            .open_secrets_z2k(0, self.num_threshold, &masked_values, true)
            .unwrap();

        // println!("Open secrets: {:?}", opened_values);

        // Compute c = t + d*s + e*r + d*e
        let results: Vec<u64> = triples
            .iter()
            .enumerate()
            .map(|(i, &(r, s, t))| {
                let d = opened_values[i * 2];
                let e = opened_values[i * 2 + 1];
                self.add_z2k_const(d * e, d * s + e * r + t, k)
                // <U64FieldEval<P>>::add(
                //     <U64FieldEval<P>>::add(t, <U64FieldEval<P>>::mul(d, s)),
                //     <U64FieldEval<P>>::add(
                //         <U64FieldEval<P>>::mul(e, r),
                //         <U64FieldEval<P>>::mul(d, e),
                //     ),
                // )
            })
            .collect();

        results
    }

    fn mul_element_wise(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Vec<Self::Sharing>> {
        assert_eq!(a.len(), b.len(), "Input vector lengths must match");
        let batch_size = a.len();

        // Get required Beaver triples
        let triples: Vec<(u64, u64, u64)> = (0..batch_size).map(|_| self.next_triple()).collect();

        // Mask inputs: d = a - r, e = b - s
        let masked_values: Vec<u64> = triples
            .iter()
            .enumerate()
            .flat_map(|(i, &(r, s, _))| {
                [
                    <U64FieldEval<P>>::sub(a[i], r),
                    <U64FieldEval<P>>::sub(b[i], s),
                ]
            })
            .collect();

        // Open masked values
        let opened_values = self
            .open_secrets_parallel(0, self.num_threshold, &masked_values, true)
            .ok_or(MPCErr::ProtocolError("Failed to open masked values".into()))?;

        // Compute c = t + d*s + e*r + d*e
        let results = triples
            .iter()
            .enumerate()
            .map(|(i, &(r, s, t))| {
                let d = opened_values[i * 2];
                let e = opened_values[i * 2 + 1];

                <U64FieldEval<P>>::add(
                    <U64FieldEval<P>>::add(t, <U64FieldEval<P>>::mul(d, s)),
                    <U64FieldEval<P>>::add(
                        <U64FieldEval<P>>::mul(e, r),
                        <U64FieldEval<P>>::mul(d, e),
                    ),
                )
            })
            .collect();

        Ok(results)
    }

    // Use double random, not beaver triples
    fn double_mul_element_wise(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Vec<Self::Sharing>> {
        assert_eq!(a.len(), b.len(), "Input vector lengths must match");
        let batch_size = a.len();
        self.mul_count = self.mul_count + batch_size as u32;
        // Get required double randoms
        let double_randoms: Vec<(u64, u64)> =
            (0..batch_size).map(|_| self.next_doublerandom()).collect();

        // Mask inputs: d = a *b +r
        let masked_values: Vec<u64> = double_randoms
            .iter()
            .enumerate()
            .flat_map(|(i, &(_, r2))| {
                [<U64FieldEval<P>>::add(
                    <U64FieldEval<P>>::mul(a[i], b[i]),
                    r2,
                )]
            })
            .collect();

        // Open masked values
        let opened_values = self
            .open_secrets_parallel(0, self.num_threshold * 2, &masked_values, true)
            .ok_or(MPCErr::ProtocolError("Failed to open masked values".into()))?;

        // Compute c = d-r
        let results = double_randoms
            .iter()
            .enumerate()
            .map(|(i, &(r_1, _))| <U64FieldEval<P>>::sub(opened_values[i], r_1))
            .collect();
        Ok(results)
    }

    fn inner_product(
        &mut self,
        a: &[Self::Sharing],
        b: &[Self::Sharing],
    ) -> MPCResult<Self::Sharing> {
        let r = a
            .iter()
            .zip(b.iter())
            .fold(0, |acc, (&a, &b)| <U64FieldEval<P>>::mul_add(a, b, acc));

        let double_random = self.next_doublerandom();
        let masked_value = <U64FieldEval<P>>::add(r, double_random.1);

        let opened_value = self
            .open_secrets_parallel(0, self.num_threshold * 2, &[masked_value], true)
            .ok_or(MPCErr::ProtocolError("Failed to open masked value".into()))?;
        self.mul_count = self.mul_count + 1;
        Ok(<U64FieldEval<P>>::sub(opened_value[0], double_random.0))
    }

    fn inner_product_const(&mut self, a: &[Self::Sharing], b: &[u64]) -> Self::Sharing {
        assert_eq!(a.len(), b.len(), "Input vector lengths must match");

        // Local computation only (no degree increase)
        let sum = a.iter().zip(b.iter()).fold(0, |acc, (&share, &constant)| {
            <U64FieldEval<P>>::mul_add(share, constant, acc)
        });

        sum
    }

    fn input(&mut self, value: Option<u64>, party_id: u32) -> MPCResult<Self::Sharing> {
        let shares = self.input_slice(value.as_ref().map(std::slice::from_ref), 1, party_id)?;
        Ok(shares[0])
    }

    fn input_slice(
        &self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> MPCResult<Vec<Self::Sharing>> {
        if party_id >= self.num_parties {
            return Err(MPCErr::ProtocolError("Invalid party ID".into()));
        }

        let shares = if self.party_id == party_id {
            self.generate_shares_streaming_and_send(
                values.expect("Dealer must provide values"),
                self.num_threshold as usize,
                (0, self.num_parties),
            )
        } else if self.party_id < self.num_parties {
            self.receive_share_column(party_id, batch_size)
        } else {
            vec![0u64; batch_size]
        };

        Ok(shares)
    }

    fn input_slice_with_prg(
        &self,
        values: Option<&[u64]>,
        batch_size: usize,
        sender_id: u32,
        degree: usize,
    ) -> MPCResult<Vec<Self::Sharing>> {
        let all_shares = if self.party_id == sender_id {
            Some(self.generate_shares_with_prg(values.unwrap(), degree))
        } else {
            None
        };

        let shares = self.share_secrets_with_prg(
            sender_id,
            batch_size,
            all_shares.as_ref(),
            // only parties P_t ~ P_{n-1} need to send
            (self.num_threshold, self.num_parties),
        );

        Ok(shares)
    }

    fn input_slice_z2k(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> Vec<u64> {
        let all_shares = if self.party_id == party_id {
            Some(self.generate_shares_z2k(values.unwrap(), self.num_threshold as usize))
        } else {
            None
        };
        let shares = self.share_secrets_parallel(
            party_id,
            batch_size,
            all_shares.as_ref(),
            (0, self.num_threshold + 1),
        );
        shares
    }

    fn sends_slice_to_all_parties(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> Vec<u64> {
        let all_shares = if self.party_id == party_id {
            let temp: Vec<Vec<u64>> = values
                .unwrap()
                .iter()
                .map(|&x| vec![x; self.num_parties as usize])
                .collect();
            Some(temp)
        } else {
            None
        };
        let shares = self.share_secrets_parallel(
            party_id,
            batch_size,
            all_shares.as_ref(),
            (0, self.num_parties),
        );
        shares
    }

    fn input_slice_with_prg_z2k(
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> Vec<u64> {
        self.send_additive_shares_z2k_with_prg(values, batch_size, party_id)
    }
    fn input_slice_with_different_party_ids(
        &mut self,
        values: &[Option<u64>],
        party_ids: &[u32],
    ) -> MPCResult<Vec<Self::Sharing>> {
        if party_ids.len() != values.len() {
            return Err(MPCErr::ProtocolError(
                "Party IDs and values must have the same length".into(),
            ));
        }

        if let Some(&invalid_id) = party_ids.iter().find(|&&id| id >= self.num_parties) {
            return Err(MPCErr::ProtocolError(format!(
                "Invalid party ID: {}",
                invalid_id
            )));
        }

        let mut values_per_party = vec![0; self.num_parties as usize];
        for &party_id in party_ids {
            values_per_party[party_id as usize] += 1;
        }

        let mut base_indices = vec![0; self.num_parties as usize];
        let mut sum = 0;
        for (i, &count) in values_per_party.iter().enumerate() {
            base_indices[i] = sum;
            sum += count;
        }

        let my_values: Vec<u64> = values
            .iter()
            .zip(party_ids)
            .filter_map(|(value, &id)| {
                if id == self.party_id {
                    value.as_ref().copied()
                } else {
                    None
                }
            })
            .collect();

        // Generate and distribute shares
        let all_shares =
            self.collect_party_shares(&values_per_party, &my_values, self.num_threshold as usize);

        let mut position_counters = vec![0; self.num_parties as usize];

        let result = party_ids
            .iter()
            .map(|&party_id| {
                let idx = party_id as usize;
                let pos = position_counters[idx];
                position_counters[idx] += 1;

                all_shares[base_indices[idx] + pos]
            })
            .collect();

        Ok(result)
    }

    fn reveal(&mut self, share: Self::Sharing, party_id: u32) -> MPCResult<Option<u64>> {
        let result = self.reveal_slice(&[share], party_id)?;

        Ok(result[0])
    }

    fn reveal_slice(
        &mut self,
        shares: &[Self::Sharing],
        party_id: u32,
    ) -> MPCResult<Vec<Option<u64>>> {
        if party_id >= self.num_parties {
            return Err(MPCErr::ProtocolError("Invalid party ID".into()));
        }

        let values = self.open_secrets_parallel(party_id, self.num_threshold, shares, false);

        let result = match (self.party_id == party_id, values) {
            (true, Some(v)) => v.into_iter().map(Some).collect(),
            (true, None) => {
                return Err(MPCErr::ProtocolError(
                    "Failed to receive reconstruction".into(),
                ))
            }
            (false, _) => vec![None; shares.len()],
        };

        Ok(result)
    }

    fn reveal_slice_z2k(&mut self, shares: &[u64], party_id: u32, k: u32) -> Vec<Option<u64>> {
        if party_id >= self.num_parties {
            return vec![None; shares.len()];
        }

        let values = self.open_secrets_z2k(party_id, self.num_threshold, shares, false);
        if k < 64 {
            let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
            match (self.party_id == party_id, values) {
                (true, Some(v)) => v.into_iter().map(|x| Some(m_mod.reduce(x))).collect(),
                (true, None) => vec![None; shares.len()],
                (false, _) => vec![None; shares.len()],
            }
        } else {
            match (self.party_id == party_id, values) {
                (true, Some(v)) => v.into_iter().map(|x| Some(x)).collect(),
                (true, None) => vec![None; shares.len()],
                (false, _) => vec![None; shares.len()],
            }
        }
    }

    fn reveal_to_all(&mut self, share: Self::Sharing) -> MPCResult<u64> {
        let result = self.reveal_slice_to_all(&[share])?;

        Ok(result[0])
    }

    fn reveal_slice_to_all(&mut self, shares: &[Self::Sharing]) -> MPCResult<Vec<u64>> {
        let results = self
            .open_secrets_parallel(0, self.num_threshold, shares, true)
            .ok_or(MPCErr::ProtocolError("Failed to reveal values".into()))?;

        Ok(results)
    }

    fn reveal_slice_to_all_z2k(&mut self, shares: &[u64], k: u32) -> Vec<u64> {
        if k < 64 {
            let m_mod = <PowOf2Modulus<u64>>::new(1u64 << k);
            self.open_secrets_z2k(0, self.num_threshold, shares, true)
                .unwrap()
                .iter()
                .map(|&x| m_mod.reduce(x))
                .collect()
        } else {
            self.open_secrets_z2k(0, self.num_threshold, shares, true)
                .unwrap()
                .iter()
                .map(|&x| x)
                .collect()
        }
    }

    fn reveal_slice_degree_2t_to_all(&mut self, shares: &[Self::Sharing]) -> MPCResult<Vec<u64>> {
        let results = self
            .open_secrets_parallel(0, self.num_threshold * 2, shares, true)
            .ok_or(MPCErr::ProtocolError("Failed to reveal values".into()))?;

        Ok(results)
    }

    fn shared_rand_coin(&mut self) -> u64 {
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

    fn create_random_elements(&mut self, length: usize) -> Vec<u64> {
        let batch_size = length.div_ceil((self.num_parties - self.num_threshold) as usize);
        let output_size = batch_size * (self.num_parties - self.num_threshold) as usize;
        let t_degree = self.num_threshold as usize;

        // Generate random a-values with t-degree polynomials
        let mut random_a = vec![0u64; batch_size];
        self.gen_random_field(&mut random_a);
        let all_a_shares = self.collect_party_shares(
            &vec![batch_size; self.num_parties as usize],
            &random_a,
            t_degree,
        );
        // let all_a_shares = self.all_parties_generate_shares_and_sends_to_all_parties(&random_a, batch_size,  t_degree);
        // Apply Vandermonde combinations to derive final shares
        let mut ret = self.vandermonde_combine(&all_a_shares, batch_size, output_size);
        ret.truncate(length);
        ret
    }

    fn ntt_sharing_poly_inplace(&self, poly: &mut [Self::Sharing]) {
        self.ntt_table.transform_slice(poly);
    }

    fn ntt_poly_inplace(&self, poly: &mut [u64]) {
        self.ntt_table.transform_slice(poly);
    }

    fn init_z2k_triples_from_files(&mut self) {
        if self.party_id() <= self.num_threshold() {
            let cwd = std::env::current_dir().unwrap();
            let path = cwd.join(format!(
                "thfhe/predata/{}/triples_P_{}.txt",
                self.num_threshold() + 1,
                self.party_id()
            ));
            self.read_z2k_triples_from_files(&path);
        }
    }

    fn test_open_secrets_z2k(
        &mut self,
        reconstructor_id: u32,
        degree: u32,
        shares: &[u64],
        broadcast_result: bool,
    ) -> Option<Vec<u64>> {
        self.open_secrets_z2k(reconstructor_id, degree, shares, broadcast_result)
    }

    fn shamir_secrets_to_additive_secrets(&mut self, shares: &[Self::Sharing]) -> Vec<u64> {
        let coeff = self.pre_shamir_to_additive_vec[self.party_id as usize];
        if self.party_id <= self.num_threshold {
            let res = shares
                .iter()
                .map(|x| <U64FieldEval<P>>::mul(*x, coeff))
                .collect();
            res
        } else {
            (0u64..=self.num_threshold as u64).collect()
        }
    }

    fn all_paries_sends_slice_to_all_parties_sum(
        &self,
        values: &[u64],
        batch_size: usize,
        sum_result: &mut [Self::Sharing],
    ) {
        let (tx, rx) = channel::unbounded::<Vec<u64>>();
        std::thread::scope(|s| {
            for i in 0..self.num_parties {
                let tx_clone = tx.clone();
                if i == self.party_id {
                    s.spawn(move || {
                        tx_clone
                            .send(
                                self.input_slice(Some(values), batch_size, self.party_id)
                                    .unwrap(),
                                //self.input_slice_with_prg(Some(values), batch_size, self.party_id, self.num_threshold as usize).unwrap(),
                            )
                            .unwrap();
                        drop(tx_clone);
                    });
                } else if i != self.party_id {
                    s.spawn(move || {
                        tx_clone
                            .send(
                                self.input_slice(None, batch_size, i).unwrap(), //self.input_slice_with_prg(None, batch_size, i,self.num_threshold as usize).unwrap()
                            )
                            .unwrap();
                        drop(tx_clone);
                    });
                };
            }
            drop(tx);
            //s.spawn(move || {
            for res in rx.iter() {
                sum_result
                    .iter_mut()
                    .zip(res.iter())
                    .for_each(|(e, res)| *e = self.add_const(*e, *res));
            }
            //});
        });
    }

    fn all_paries_sends_slice_to_all_parties_sum_with_prg(
        &self,
        values: &[u64],
        batch_size: usize,
        sum_result: &mut [Self::Sharing],
    ) {
        let (tx, rx) = channel::unbounded::<Vec<u64>>();

        std::thread::scope(|s| {
            for i in 0..self.num_parties {
                let tx_clone = tx.clone();

                if i == self.party_id {
                    s.spawn(move || {
                        tx_clone
                            .send(
                                self.input_slice_with_prg(
                                    Some(values),
                                    batch_size,
                                    self.party_id,
                                    self.num_threshold as usize,
                                )
                                .unwrap(),
                            )
                            .unwrap();
                        drop(tx_clone);
                    });
                } else if i != self.party_id {
                    s.spawn(move || {
                        tx_clone
                            .send(
                                self.input_slice_with_prg(
                                    None,
                                    batch_size,
                                    i,
                                    self.num_threshold as usize,
                                )
                                .unwrap(),
                            )
                            .unwrap();
                        drop(tx_clone);
                    });
                };
            }
            drop(tx);
            //s.spawn(move || {
            for res in rx.iter() {
                sum_result
                    .iter_mut()
                    .zip(res.iter())
                    .for_each(|(e, res)| *e = self.add_const(*e, *res));
            }
            //});
        });
    }
}
