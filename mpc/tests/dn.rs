use algebra::{Field, U64FieldEval};
use mpc::{DNBackend, MPCBackend};
use network::netio::Participant;
use std::thread;

// Prime field modulus for tests.
const PRIME: u64 = 2305843009213693951; // 2^61 - 1

/// Tests secret sharing and reconstruction between parties.
/// Verifies that shares can be properly distributed and recombined.
#[test]
fn test_secret_sharing_and_recovery() {
    const NUM_PARTIES: u32 = 3;
    const THRESHOLD: u32 = 1;
    const BASE_PORT: u32 = 50000;

    let secrets: Vec<u64> = vec![123456789, 987654321, 42, PRIME - 1];

    // Create threads for each party to simulate network communication.
    let mut threads = Vec::new();

    for id in 0..NUM_PARTIES {
        let secrets = secrets.clone();
        threads.push(thread::spawn(move || {
            // Setup the DN backend.
            let participants = Participant::from_default(NUM_PARTIES, BASE_PORT);
            let mut dn =
                DNBackend::<PRIME>::new(id, NUM_PARTIES, THRESHOLD, 10, participants, 1024);

            // Test input and reveal_to_all for each secret.
            for secret in secrets {
                // Each party takes turns being the dealer.
                for dealer_id in 0..NUM_PARTIES {
                    // Only the dealer provides the input value.
                    let input_value = if id == dealer_id { Some(secret) } else { None };
                    let share = dn.input(input_value, dealer_id).unwrap();

                    // All parties reveal and verify.
                    let result = dn.reveal_to_all(share).unwrap();
                    assert_eq!(result, secret, "Party {id} got incorrect result");
                }
            }

            // Additional test: Party 0 reveals to party 1 only.
            if id == 0 {
                let value = 999;
                let share = dn.input(Some(value), 0).unwrap();
                let reveal_result = dn.reveal(share, 1).unwrap();
                assert_eq!(reveal_result, None); // Party 0 doesn't get the result.
            } else if id == 1 {
                let share = dn.input(None, 0).unwrap();
                let reveal_result = dn.reveal(share, 1).unwrap();
                assert_eq!(reveal_result, Some(999)); // Party 1 gets the result.
            }

            // Return success if all tests passed for this party.
            true
        }));
    }

    // Verify all threads succeeded.
    for handle in threads {
        assert!(handle.join().unwrap());
    }
}

/// Tests the correctness of Beaver triples generation and usage.
/// Verifies that triples satisfy the relation c = a*b and can be used in multiplications.
#[test]
fn test_triple_correctness() {
    const NUM_PARTIES: u32 = 7;
    const THRESHOLD: u32 = 3;
    const BASE_PORT: u32 = 51400;
    const NUM_TRIPLES: u32 = 100;

    let mut threads = Vec::new();

    for id in 0..NUM_PARTIES {
        threads.push(thread::spawn(move || {
            // Setup the DN backend.
            let participants = Participant::from_default(NUM_PARTIES, BASE_PORT);
            let mut dn = DNBackend::<PRIME>::new(
                id,
                NUM_PARTIES,
                THRESHOLD,
                NUM_TRIPLES,
                participants,
                1024,
            );

            for _ in 0..NUM_TRIPLES / 2 {
                // Get a triple from the buffer.
                let (share_a, share_b, share_c) = dn.next_triple();

                // Reveal all values.
                let revealed_a = dn.reveal_to_all(share_a).unwrap();
                let revealed_b = dn.reveal_to_all(share_b).unwrap();
                let revealed_c = dn.reveal_to_all(share_c).unwrap();

                let calculated_c = dn.mul(share_a, share_b).unwrap();

                // Verify that the revealed c matches a*b.
                let expected = U64FieldEval::<PRIME>::mul(revealed_a, revealed_b);
                let revealed_calculated_c = dn.reveal_to_all(calculated_c).unwrap();
                assert_eq!(
                    revealed_c, expected,
                    "Revealed triple is incorrect: c ≠ a*b"
                );

                // Verify that our calculated c matches the original c.
                assert_eq!(
                    revealed_calculated_c, revealed_c,
                    "Calculated c doesn't match original c"
                );
            }

            true
        }));
    }

    // Verify all threads succeeded.
    for handle in threads {
        assert!(handle.join().unwrap());
    }
}

/// Tests basic MPC operations including addition, multiplication, and other core functions.
/// Verifies correctness of operations with different input values.
#[test]
fn test_mpc_operations() {
    const NUM_PARTIES: u32 = 7;
    const THRESHOLD: u32 = 3;
    const BASE_PORT: u32 = 50200;

    let mut threads = Vec::new();

    for id in 0..NUM_PARTIES {
        threads.push(thread::spawn(move || {
            // Setup the DN backend.
            let participants = Participant::from_default(NUM_PARTIES, BASE_PORT);
            let mut dn =
                DNBackend::<PRIME>::new(id, NUM_PARTIES, THRESHOLD, 20, participants, 1024);

            // Test 1: Addition.
            let a_value = 42;
            let b_value = 99;

            // Each party gets shares.
            let share_a = if id == 0 {
                dn.input(Some(a_value), 0).unwrap()
            } else {
                dn.input(None, 0).unwrap()
            };

            let share_b = if id == 1 {
                dn.input(Some(b_value), 1).unwrap()
            } else {
                dn.input(None, 1).unwrap()
            };

            // Addition (local operation).
            let share_sum = dn.add(share_a, share_b);
            let sum_result = dn.reveal_to_all(share_sum).unwrap();
            assert_eq!(
                sum_result,
                U64FieldEval::<PRIME>::add(a_value, b_value),
                "Addition failed"
            );

            // Test 2: Multiplication (requires communication).
            let share_prod = dn.mul(share_a, share_b).unwrap();
            let prod_result = dn.reveal_to_all(share_prod).unwrap();
            assert_eq!(
                prod_result,
                U64FieldEval::<PRIME>::mul(a_value, b_value),
                "Multiplication failed"
            );

            // Test 3: Batch multiplication.
            let shares_a = vec![share_a, share_a, share_a];
            let shares_b = vec![share_b, share_b, share_b];

            let shares_prod = dn.mul_element_wise(&shares_a, &shares_b).unwrap();
            assert_eq!(shares_prod.len(), 3, "Batch size mismatch");

            for share_p in shares_prod {
                let result = dn.reveal_to_all(share_p).unwrap();
                assert_eq!(
                    result,
                    U64FieldEval::<PRIME>::mul(a_value, b_value),
                    "Batch multiplication failed"
                );
            }

            // Test 4: Inner product.
            let values_a = vec![1, 2, 3];
            let values_b = vec![4, 5, 6];
            let expected_dot = U64FieldEval::<PRIME>::add(
                U64FieldEval::<PRIME>::add(
                    U64FieldEval::<PRIME>::mul(1, 4),
                    U64FieldEval::<PRIME>::mul(2, 5),
                ),
                U64FieldEval::<PRIME>::mul(3, 6),
            );

            let shares_a: Vec<_> = values_a
                .iter()
                .enumerate()
                .map(|(i, &v)| {
                    if id as usize == i % NUM_PARTIES as usize {
                        dn.input(Some(v), id).unwrap()
                    } else {
                        dn.input(None, i as u32 % NUM_PARTIES).unwrap()
                    }
                })
                .collect();

            let shares_b: Vec<_> = values_b
                .iter()
                .enumerate()
                .map(|(i, &v)| {
                    if id as usize == i % NUM_PARTIES as usize {
                        dn.input(Some(v), id).unwrap()
                    } else {
                        dn.input(None, i as u32 % NUM_PARTIES).unwrap()
                    }
                })
                .collect();

            let dot_share = dn.inner_product(&shares_a, &shares_b).unwrap();
            let dot_result = dn.reveal_to_all(dot_share).unwrap();
            assert_eq!(dot_result, expected_dot, "Inner product failed");

            true
        }));
    }

    for handle in threads {
        assert!(handle.join().unwrap());
    }
}

/// Tests additional MPC operations including negation, subtraction, and various constant operations.
/// Verifies correctness of operations not covered in the basic operations test.
#[test]
fn test_untested_operations() {
    const NUM_PARTIES: u32 = 7;
    const THRESHOLD: u32 = 3;
    const BASE_PORT: u32 = 50500;

    let mut threads = Vec::new();

    for id in 0..NUM_PARTIES {
        threads.push(thread::spawn(move || {
            // Setup the DN backend.
            let participants = Participant::from_default(NUM_PARTIES, BASE_PORT);
            let mut dn =
                DNBackend::<PRIME>::new(id, NUM_PARTIES, THRESHOLD, 20, participants, 1024);

            // Test values.
            let a_value = 42;
            let b_value = 7;

            // Get shares.
            let share_a = if id == 0 {
                dn.input(Some(a_value), 0).unwrap()
            } else {
                dn.input(None, 0).unwrap()
            };

            let share_b = if id == 1 {
                dn.input(Some(b_value), 1).unwrap()
            } else {
                dn.input(None, 1).unwrap()
            };

            // 1. Test neg operation.
            let neg_share = dn.neg(share_a);
            let neg_result = dn.reveal_to_all(neg_share).unwrap();
            assert_eq!(
                neg_result,
                U64FieldEval::<PRIME>::neg(a_value),
                "Negation failed"
            );

            // 2. Test sub operation.
            let sub_share = dn.sub(share_a, share_b);
            let sub_result = dn.reveal_to_all(sub_share).unwrap();
            assert_eq!(
                sub_result,
                U64FieldEval::<PRIME>::sub(a_value, b_value),
                "Subtraction failed"
            );

            // 3. Test mul_const operation.
            let const_value = 13;
            let mul_const_share = dn.mul_const(share_a, const_value);
            let mul_const_result = dn.reveal_to_all(mul_const_share).unwrap();
            assert_eq!(
                mul_const_result,
                U64FieldEval::<PRIME>::mul(a_value, const_value),
                "Multiplication by constant failed"
            );

            // 4. Test double operation.
            let double_share = dn.double(share_a);
            let double_result = dn.reveal_to_all(double_share).unwrap();
            assert_eq!(
                double_result,
                U64FieldEval::<PRIME>::add(a_value, a_value),
                "Double operation failed"
            );

            // 5. Test inner_product_const operation.
            let shares = vec![share_a, share_b, share_a];
            let constants = vec![3, 4, 5];
            let expected_inner = U64FieldEval::<PRIME>::add(
                U64FieldEval::<PRIME>::add(
                    U64FieldEval::<PRIME>::mul(a_value, 3),
                    U64FieldEval::<PRIME>::mul(b_value, 4),
                ),
                U64FieldEval::<PRIME>::mul(a_value, 5),
            );

            let inner_const_share = dn.inner_product_const(&shares, &constants);
            let inner_const_result = dn.reveal_to_all(inner_const_share).unwrap();
            assert_eq!(
                inner_const_result, expected_inner,
                "Inner product with constants failed"
            );

            true
        }));
    }

    for handle in threads {
        assert!(handle.join().unwrap());
    }
}

/// Tests that rand_coin returns consistent values across all parties.
/// Verifies that the shared PRG produces identical sequences for each party.
#[test]
fn test_rand_coin_consistency() {
    const NUM_PARTIES: u32 = 4;
    const THRESHOLD: u32 = 1;
    const BASE_PORT: u32 = 50800;
    const NUM_COINS: usize = 10000;

    let mut threads = Vec::new();

    // Create a channel to collect results from all parties
    let (tx, rx) = std::sync::mpsc::channel();

    for id in 0..NUM_PARTIES {
        let tx = tx.clone();
        threads.push(thread::spawn(move || {
            // Setup the DN backend
            let participants = Participant::from_default(NUM_PARTIES, BASE_PORT);
            let mut dn = DNBackend::<PRIME>::new(id, NUM_PARTIES, THRESHOLD, 5, participants, 1024);

            // Generate a sequence of random coins
            let mut coins = Vec::with_capacity(NUM_COINS);
            for _ in 0..NUM_COINS {
                coins.push(dn.shared_rand_coin());
            }

            // Send party ID and coin values to the main thread
            tx.send((id, coins)).unwrap();
            true
        }));
    }

    // Collect all results
    drop(tx); // Drop the extra sender so the receiver knows when to stop
    let mut all_results = Vec::new();
    while let Ok((id, coins)) = rx.recv() {
        all_results.push((id, coins));
    }

    // Verify all parties got the same values
    if !all_results.is_empty() {
        let reference_coins = &all_results[0].1;
        for (id, coins) in &all_results[1..] {
            assert_eq!(
                coins, reference_coins,
                "Party {id} got different random coins than party 0"
            );
        }
    }

    // Wait for all threads to complete
    for handle in threads {
        assert!(handle.join().unwrap());
    }
}
