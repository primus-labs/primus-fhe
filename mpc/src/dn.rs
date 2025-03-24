//! DN07 protocol implementation (Damgård-Nielsen 2007) for honest-majority MPC.
//! Provides t-privacy in an (n,t) threshold setting where n > 2t.

use crate::{error::MPCErr, MPCBackend, MPCResult};
use algebra::ntt::NumberTheoryTransform;
use algebra::random::Prg;
use algebra::reduce::ReduceInv;
use algebra::{Field, NttField, U64FieldEval};
use bytemuck::{cast_slice, cast_slice_mut};
use network::netio::{NetIO, Participant};
use network::IO;
use rand::distributions::Uniform;
use rand::prelude::Distribution;
use rand::{RngCore, SeedableRng};
use std::collections::VecDeque;
use std::ops::Mul;
use std::result;
///use std::intrinsics::abort;

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
    pub netio: NetIO,

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
    // Buffer size for triple generation over z2k
    triplez2k_buffer_capacity: usize,
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

            triplez2k_buffer: VecDeque::new(),
            triplez2k_buffer_capacity: buffer_size,

            doublerandom_buffer: VecDeque::with_capacity(buffer_size),
            doublerandom_buffer_capacity: buffer_size,

            uniform_distr: Uniform::new(0, P),
            ntt_table: <U64FieldEval<P> as NttField>::generate_ntt_table(
                polynomial_size.trailing_zeros(),
            )
            .unwrap(),
        };

        // Generate initial supply of triples
        // backend.generate_triples(buffer_size);
        // backend

        // Generate initial supply of triples
        backend.generate_doublerandoms(buffer_size);
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
                    .map(|j| <U64FieldEval<P>>::mul(positions[j], matrix[i - 1][j]))
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
    fn setup_shared_prg(party_id: u32, num_parties: u32, prg: &mut Prg, netio: &mut NetIO) -> Prg {
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
        let party_id = self.party_id() as usize; // 假设返回 usize

        let mut shares = Vec::with_capacity(values.len());

        for &val in values.iter() {
            let mut row = vec![0u64; num_parties];
            let mut sum = 0u64;

            for i in 0..num_parties {
                if i != party_id {
                    let rand = self.prg.next_u64();
                    row[i] = rand;
                    sum = sum + rand; // 防止 u64 溢出
                }
            }

            // 当前方负责补足剩余值（值减去其余 share）
            row[party_id] = val - sum; // 用 wrapping 保证不 panic
            shares.push(row);
        }
        shares
    }

    /// compute inv of van martix
    // fn van_inver(&mut self){
    //     let msize = (self.num_threshold()+1) as usize;
    //     let mut inv_l_martix:Vec<Vec<u64>> = vec![vec![0; msize]; msize];
    //     let mut inv_u_martix:Vec<Vec<u64>> = vec![vec![0; msize]; msize];
    //     inv_l_martix[0][0] = 1;
    //     let modulus = self.modulus();
    //     let x_martix:Vec<u64> =(1 as u64..=msize as u64).map(|x| x).collect();
    //     for i in 0..msize{
    //         for j in 0..msize{
    //             if i<j {
    //                 inv_l_martix[i][j] = 0;
    //             }else{
    //                 let mut temp:u64 = 1;
    //                 for k in 0..=i{
    //                     if j!=k{
    //                         temp = temp*modulus.reduce_inv(x_martix[j]-x_martix[k]);
    //                     }
    //                 }
    //                 inv_l_martix[i][j] = temp;
    //             }
    //         }
    //     }

    //     for i in 0..msize{
    //         for j in 0..msize{
    //             if i==j{
    //                 inv_u_martix[i][j] = 1;
    //             }else if i>j {
    //                 inv_u_martix[i][j] = 0;
    //             }
    //         }
    //     }
    // }
    /// 计算给定 Vandermonde 矩阵的逆矩阵（模素数 p）。
    /// 输入 `vander` 是 Vandermonde 矩阵（Vec<Vec<u64>> 格式），其中第 i 行对应节点 x_i 的 [1, x_i, x_i^2, ..., x_i^{n-1}]。
    /// 返回与之对应的逆矩阵（模 p）。
    fn inverse_vandermonde_mod_p(&mut self, vander: Vec<Vec<u64>>, p: u64) -> Vec<Vec<u64>> {
        let n = vander.len();
        assert!(n > 0 && vander[0].len() == n, "输入矩阵必须是 n x n 的方阵");
        // 提取节点值 x_i。假定输入矩阵满足定义，第 i 行第二个元素即为 x_i（索引从0计则为 vander[i][1]）。
        let mut x = Vec::with_capacity(n);
        for i in 0..n {
            if n > 1 {
                x.push(vander[i][1] % p);
            } else {
                x.push(0u64); // 如果只有1x1矩阵，x[0]的值无关紧要（不会用到）。
            }
        }

        // 工具闭包：计算 (a + b) mod p 和 (a * b) mod p，使用 u128 防止溢出。
        let mut add_mod =
            |a: u64, b: u64| -> u64 { ((a as u128 + b as u128) % (p as u128)) as u64 };
        let mut mul_mod =
            |a: u64, b: u64| -> u64 { ((a as u128 * b as u128) % (p as u128)) as u64 };

        // 计算乘法逆元的函数，使用扩展欧几里得算法求 a 在 mod p 下的逆（假定 p 是素数且 a 与 p 共质）。
        fn mod_inv(a: u64, p: u64) -> u64 {
            // 扩展欧几里得算法求 ax + py = 1 中的 x
            let (mut r0, mut r1) = (a as i64, p as i64);
            let (mut t0, mut t1) = (1i64, 0i64);
            while r1 != 0 {
                let q = r0 / r1;
                (r0, r1) = (r1, r0 - q * r1);
                (t0, t1) = (t1, t0 - q * t1);
            }
            // 确保结果为正的 mod 值
            let inv = if t0 < 0 { t0 + p as i64 } else { t0 };
            inv as u64
        }

        // 构造并计算 L^{-1} 矩阵（n x n，下三角）。
        let mut inv_l = vec![vec![0u64; n]; n];
        for i in 0..n {
            // 计算 L_{ii} 的值：L_{ii} = ∏_{m=1}^{i} (x_{i+1} - x_m)，注意索引换算（i从0开始，对应x_{i+1}）。
            // 这里我们用 0..i-1（0-based）来表示 1..i（1-based）的下标范围。
            let mut diag_val = 1u64;
            for m in 0..i {
                // (x_{i+1} - x_{m+1}) mod p
                let diff = if x[m] <= x[i] {
                    (x[i] - x[m]) % p
                } else {
                    // 避免负数，先加 p 再减
                    ((x[i] + p) - x[m]) % p
                };
                diag_val = mul_mod(diag_val, diff);
            }
            // 计算对角元素在模 p 下的逆元
            let inv_diag = if diag_val % p == 0 {
                panic!("差值乘积 mod p 为0，x_i-x_j 与 p 不是互素，无法求逆");
            } else {
                mod_inv(diag_val % p, p)
            };
            inv_l[i][i] = inv_diag;
            // 递推求解 L^{-1} 当前行的其他元素 (i > j)：
            // (L^{-1})_{i,j} = - L_{ii}^{-1} * ∑_{k=j}^{i-1} L_{i,k} * (L^{-1})_{k,j}
            // 利用已计算的较小行的 L^{-1} 值。
            for j in 0..i {
                // 计算∑_{k=j}^{i-1} L_{i,k} * (L^{-1})_{k,j}
                let mut sum = 0u64;
                for k in j..i {
                    // 先计算 L_{i,k}。根据前述 L 的结构，当 k< i：
                    // L_{i,k} = ∏_{m=1}^{k-1}(x_i - x_m) （注意 m 范围 1..k-1 对应 0..k-2 的索引）。
                    // 为了高效，这里可以利用已有的部分差积：
                    // 实际上，对于固定 i，随着 k 从 j 到 i-1 增加，我们的差积是在逐渐增加因子。
                    // 但为简单起见，此处直接根据定义计算或使用 vander 矩阵提供的值：
                    let l_ik = if k == 0 {
                        1u64 // L_{i,1} = 1
                    } else {
                        // L_{i,k} 可以从输入的 Vandermonde 矩阵中获取：第 i 行（索引 i）的第 k 列元素并不直接是 L_{i,k}，
                        // 但注意第 i 行第 k 列（0-based索引） = x_i^k = ∏_{m=1}^{k}(x_i) （这不是所需形式）。
                        // 因此我们还是按定义计算:
                        let mut prod = 1u64;
                        for m in 0..k {
                            // m 对应 1..k 的原公式 (1-based)，这里 0..k-1
                            let diff = if x[m] <= x[i] {
                                (x[i] - x[m]) % p
                            } else {
                                ((x[i] + p) - x[m]) % p
                            };
                            prod = mul_mod(prod, diff);
                        }
                        prod
                    };
                    // 累加 L_{i,k} * (L^{-1})_{k,j}
                    sum = add_mod(sum, mul_mod(l_ik, inv_l[k][j]));
                }
                // 取负号再乘以 L_{ii}^{-1}（即 inv_diag）
                let neg_sum = if sum == 0 { 0 } else { p - (sum % p) };
                inv_l[i][j] = mul_mod(inv_diag, neg_sum % p);
            }
        }

        // 构造并计算 U^{-1} 矩阵（n x n，上三角）。
        let mut inv_u = vec![vec![0u64; n]; n];
        // 上三角矩阵 U^{-1} 的递推公式：
        // (U^{-1})_{ii} = 1; (U^{-1})_{i,1} = 0 (i>1);
        // 对于 i<j: (U^{-1})_{i,j} = (U^{-1})_{i-1, j-1} - x_{j-1} * (U^{-1})_{i, j-1}.
        for i in 0..n {
            for j in i..n {
                if i == j {
                    inv_u[i][j] = 1; // 对角线元素
                } else if i < j {
                    // 注意索引转换：我们用 0 基索引，x[j-1] 对应公式中的 x_{j}（1 基）；
                    // 公式中的 (U^{-1})_{i-1,j-1} 对应 inv_u[i-1][j-1] （当 i>0 时）。
                    let term1 = if i == 0 { 0 } else { inv_u[i - 1][j - 1] };
                    let term2 = mul_mod(x[j - 1], inv_u[i][j - 1]);
                    // 相减取模
                    inv_u[i][j] = if term1 >= term2 {
                        (term1 - term2) % p
                    } else {
                        (term1 + p - term2) % p // 避免出现负值
                    };
                }
                // 对于 i > j 的下三角部分，inv_u 默认为 0（无需赋值）。
            }
        }

        // 最后计算 A^{-1} = U^{-1} * L^{-1}，矩阵乘法结果仍取模 p。
        let mut inv_matrix = vec![vec![0u64; n]; n];
        for i in 0..n {
            // 遍历结果矩阵的第 i 行
            for j in 0..n {
                // 遍历结果矩阵的第 j 列
                let mut sum = 0u64;
                for k in 0..n {
                    // inv_u 的第 i 行 k 列 与 inv_l 的第 k 行 j 列的乘积累加
                    // 由于 U^{-1} 为上三角矩阵、L^{-1} 为下三角矩阵，可考虑跳过不必要的 k，
                    // 但这里为清晰起见仍遍历 0..n 后续通过值为0自动忽略。
                    sum = add_mod(sum, mul_mod(inv_u[i][k], inv_l[k][j]));
                }
                inv_matrix[i][j] = sum;
            }
        }
        inv_matrix
    }

    /// Distributes shares from a dealer to selected parties.
    fn share_secrets(
        &mut self,
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
            // Not in target range, return empty shares
            vec![0u64; batch_size]
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

        const MAX_BATCH_SIZE: usize = 128;
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
        let output_size = batch_size * (self.num_parties - self.num_threshold) as usize;
        let t_degree = self.num_threshold as usize;

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
        let mask_t_shares = self.vandermonde_combine(&all_mask_t_shares, batch_size, output_size);
        let mask_2t_shares = self.vandermonde_combine(&all_mask_2t_shares, batch_size, output_size);

        //return result
        let ret: Vec<(u64, u64)> = mask_t_shares
            .iter()
            .cloned()
            .zip(mask_2t_shares.iter().cloned())
            .collect();
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
            let party_shares = self.share_secrets(
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
            let party_shares =
                self.share_secrets(party_idx, size[party_idx as usize], shares, (0, party_idx));
            if party_idx > self.party_id {
                all_shares.extend_from_slice(&party_shares);
            }
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

    /// Gets the next available double random.
    pub fn next_doublerandom(&mut self) -> (u64, u64) {
        if self.doublerandom_buffer.is_empty() {
            self.generate_doublerandoms(self.doublerandom_buffer_capacity);
        }

        self.doublerandom_buffer.pop_front().unwrap()
    }

    /// read z2k beaver triples from files
    pub fn read_z2k_triples_from_files(&mut self, filename: &str) {
        //println!("read file {}",filename);
        use std::fs;
        use std::str::FromStr;
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
    }

    /// next z2k triple
    pub fn next_triple_z2k(&mut self) -> (u64, u64, u64) {
        if self.triplez2k_buffer.is_empty() {
            panic!("Triples over tiples finished");
        }

        self.triplez2k_buffer.pop_front().unwrap()
    }

    /// Reconstructs secrets from shares through polynomial interpolation.
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

    fn modinv(&mut self, a: u64, p: u64) -> u64 {
        // 求 a^(-1) mod p，使用扩展欧几里得算法
        let (mut a, mut b, mut u) = (a as i64, p as i64, 1i64);
        let mut v = 0i64;
        while b != 0 {
            let q = a / b;
            a = a - q * b;
            std::mem::swap(&mut a, &mut b);
            u = u - q * v;
            std::mem::swap(&mut u, &mut v);
        }
        assert!(a == 1, "No inverse exists");
        ((u + p as i64) % p as i64) as u64
    }

    // fn vandermonde_inverse_first_row(&mut self, n: usize, p: u64) -> Vec<u64> {
    //     let x: Vec<u64> = (0..=n as u64).collect(); // x = [0, 1, ..., n]
    //     let mut first_row = vec![0u64; n + 1];

    //     for j in 0..=n {
    //         let mut prod = 1u64;
    //         for m in 0..=n {
    //             if m != j {
    //                 let denom = (x[j] + p - x[m]) % p;
    //                 prod = prod * self.modinv(denom, p) % p;
    //             }
    //         }
    //         // Now compute each entry in the first row
    //         for k in 0..=n {
    //             let mut term = 0u64;
    //             for m in 0..=n {
    //                 if m != j {
    //                     let mut num = 1u64;
    //                     for l in 0..=n {
    //                         if l != j && l != m {
    //                             num = num * (p - x[l]) % p;
    //                         }
    //                     }
    //                     let denom = (x[j] + p - x[m]) % p;
    //                     let denom_inv = self.modinv(denom, p);
    //                     let sign = if (j + m) % 2 == 0 { 1 } else { p - 1 };
    //                     term = (term + sign * num % p * denom_inv % p) % p;
    //                 }
    //             }
    //             if k == 0 {
    //                 first_row[j] = prod;
    //             }
    //         }
    //     }
    //     first_row
    // }
    // 求拉格朗日插值多项式的系数，返回 n+1 长度的 Vec<u64>
    fn lagrange_basis_inverse_matrix(&mut self, xs: &[u64], p: u64) -> Vec<Vec<u64>> {
        let n = xs.len();
        let mut inv_matrix = vec![vec![0u64; n]; n];

        // 对每一个单位向量 e_i 构造拉格朗日插值多项式
        for i in 0..n {
            // 构造 y 向量: y[j] = 1 if j == i, else 0
            let mut coeffs = vec![0u64; n];
            for j in 0..n {
                if i == j {
                    continue;
                }
                let denom = (xs[i] + p - xs[j]) % p;
                let denom_inv = self.modinv(denom, p);
                for k in (0..n).rev() {
                    coeffs[k] = if k == 0 { 0 } else { coeffs[k - 1] };
                }
                for k in 0..n {
                    coeffs[k] = (p + coeffs[k] + p - xs[j] * coeffs[k] % p) % p;
                }
                let scale = denom_inv;
                for k in 0..n {
                    coeffs[k] = coeffs[k] * scale % p;
                }
            }
            // 把这个插值多项式的系数作为第 i 行（或列）
            for k in 0..n {
                inv_matrix[i][k] = coeffs[k];
            }
        }

        inv_matrix
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
            return <U64FieldEval<P>>::sub(a, b);
        } else {
            return <U64FieldEval<P>>::neg(b);
        }
    }

    fn mul_additive_const_p(&mut self, a: u64, b: u64) -> u64 {
        return <U64FieldEval<P>>::mul(a, b);
    }

    fn inner_product_additive_const_p(&mut self, a: &[u64], b: &[u64]) -> u64 {
        let sum = a.iter().zip(b.iter()).fold(0, |acc, (&share, &constant)| {
            <U64FieldEval<P>>::mul_add(share, constant, acc)
        });
        sum
    }

    /// return additive secret sharing of a-b where a is const and b is additive sharing
    fn sub_z2k_const(&mut self, a: u64, b: u64) -> u64 {
        if self.party_id() == 0 {
            return a - b;
        } else {
            return 0 - b;
        }
    }

    /// return additive secret sharing of a+b where a is const and b is additive sharing
    fn add_z2k_const(&mut self, a: u64, b: u64) -> u64 {
        if self.party_id() == 0 {
            return a + b;
        } else {
            return b;
        }
    }

    fn add_z2k_slice(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), b.len(), "vectors must be of the same length");

        a.iter().zip(b.iter()).map(|(x, y)| x + y).collect()
    }

    fn sub_z2k_slice(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), b.len(), "vectors must be of the same length");

        a.iter().zip(b.iter()).map(|(x, y)| x - y).collect()
    }

    fn double_z2k_slice(&self, a: &[u64]) -> Vec<u64> {
        a.iter().map(|x| 2 * x).collect()
    }

    fn double(&self, a: Self::Sharing) -> Self::Sharing {
        <U64FieldEval<P>>::double(a)
    }

    fn add_const(&self, a: Self::Sharing, b: u64) -> Self::Sharing {
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

    fn mul_element_wise_z2k(&mut self, a: &[u64], b: &[u64]) -> Vec<u64> {
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
                self.add_z2k_const(d * e, d * s + e * r + t)
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
            .open_secrets(0, self.num_threshold, &masked_values, true)
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
            .open_secrets(0, self.num_threshold * 2, &masked_values, true)
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
            .open_secrets(0, self.num_threshold as u32 * 2, &[masked_value], true)
            .ok_or(MPCErr::ProtocolError("Failed to open masked value".into()))?;

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
        &mut self,
        values: Option<&[u64]>,
        batch_size: usize,
        party_id: u32,
    ) -> MPCResult<Vec<Self::Sharing>> {
        if party_id >= self.num_parties {
            return Err(MPCErr::ProtocolError("Invalid party ID".into()));
        }

        let all_shares = if self.party_id == party_id {
            Some(self.generate_shares(values.unwrap(), self.num_threshold as usize))
        } else {
            None
        };

        let shares = self.share_secrets(
            party_id,
            batch_size,
            all_shares.as_ref(),
            (0, self.num_parties),
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
        let shares = self.share_secrets(
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
        let shares = self.share_secrets(
            party_id,
            batch_size,
            all_shares.as_ref(),
            (0, self.num_parties),
        );
        shares
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

        let values = self.open_secrets(party_id, self.num_threshold, shares, false);

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

    fn reveal_slice_z2k(&mut self, shares: &[u64], party_id: u32) -> Vec<Option<u64>> {
        if party_id >= self.num_parties {
            return vec![None; shares.len()];
        }

        let values = self.open_secrets_z2k(party_id, self.num_threshold, shares, false);

        let result = match (self.party_id == party_id, values) {
            (true, Some(v)) => v.into_iter().map(Some).collect(),
            (true, None) => vec![None; shares.len()],
            (false, _) => vec![None; shares.len()],
        };
        result
    }

    fn reveal_to_all(&mut self, share: Self::Sharing) -> MPCResult<u64> {
        let result = self.reveal_slice_to_all(&[share])?;

        Ok(result[0])
    }

    fn reveal_slice_to_all(&mut self, shares: &[Self::Sharing]) -> MPCResult<Vec<u64>> {
        let results = self
            .open_secrets(0, self.num_threshold, shares, true)
            .ok_or(MPCErr::ProtocolError("Failed to reveal values".into()))?;

        Ok(results)
    }

    fn reveal_slice_to_all_z2k(&mut self, shares: &[u64]) -> Vec<u64> {
        let results = self
            .open_secrets_z2k(0, self.num_threshold, &shares, true)
            .unwrap();
        results
    }

    fn reveal_slice_degree_2t_to_all(&mut self, shares: &[Self::Sharing]) -> MPCResult<Vec<u64>> {
        let results = self
            .open_secrets(0, self.num_threshold * 2, shares, true)
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
            //println!("Current working directory: {:?}", cwd);
            let filename = format!(
                "{}\\thfhe\\predata\\triples_P_{}.txt",
                cwd.to_string_lossy().into_owned(),
                self.party_id()
            );
            self.read_z2k_triples_from_files(&filename);
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
        let msize = (self.num_threshold + 1) as usize;
        let mut van_t: Vec<Vec<u64>> = vec![vec![0; msize]; msize];
        for i in 0..msize {
            for j in 0..msize {
                van_t[i][j] = self.van_matrix[j][i];
            }
        }
        let res = self.inverse_vandermonde_mod_p(van_t, self.modulus().value());
        if self.party_id <= self.num_threshold {
            let res = shares
                .iter()
                .map(|x| <U64FieldEval<P>>::mul(*x, res[0][(self.party_id) as usize]))
                .collect();
            res
        } else {
            return (0 as u64..=self.num_threshold as u64).collect();
        }
    }
}
