use algebra::{modulus::PowOf2Modulus, AsInto, U64FieldEval};
use fhe_cmp::{
    CmpFheParameters, Decryptor, Encryptor, FheCompare, KeyGen, LVL2PARAM_128_BITS_PARAMETERS,
};
use fhe_core::LweCiphertext;
use rand::{thread_rng, Rng};
// Importing rayon library to parallelize operations
use rayon::prelude::*; 
// Import Arc and Mutex to implement thread-safe shared data
use std::sync::{Arc, Mutex}; 
use std::time::Instant;

type M = u64;
type Fp = U64FieldEval<4179340454199820289>;
type LweModulus = PowOf2Modulus<u64>;
fn main() {
    let params = *LVL2PARAM_128_BITS_PARAMETERS;
    // Set the number of valid bits for the plaintext and total tests
    let plain_modulus_bits: u32 = 9; //support 33bit
    let total_tests: u32 = 32;
    let if_run_thread: bool = true;

    if if_run_thread {
        // Running multi-threaded tests
        println!("\nRunning multi-threaded tests...");
        msb_multi_threaded_tests(plain_modulus_bits, total_tests, params);
        cmp_multi_threaded_tests(plain_modulus_bits, total_tests, params);
    } else {
        // Running single-threaded tests
        println!("Running single-threaded tests...");
        msb_single_threaded_tests(plain_modulus_bits, total_tests, params);
        cmp_single_threaded_tests(plain_modulus_bits, total_tests, params);
    }
}

/// A single-threaded function that tests extracting the Most Significant Bit (MSB)
/// from homomorphically encrypted data. It randomly generates numbers, encrypts them,
/// extracts their MSB homomorphically, and compares the result to the expected MSB.
///
/// # Arguments
/// * `plain_modulus_bits` - The bit-size of the plaintext modulus range.
/// * `total_tests`        - The total number of tests to run.
/// * `params`             - The parameters used for key generation, encryption, and decryption.
fn msb_single_threaded_tests(
    plain_modulus_bits: u32,
    total_tests: u32,
    params: CmpFheParameters<M, LweModulus, Fp>,
) {
    // Set the modulus to (q - 1) for BrMsKs (Bootstrap + Relinearization) mode conversion.
    let modulus = <PowOf2Modulus<M>>::new_with_mask(params.lwe_cipher_modulus_minus_one());

    // Start timing the entire testing process.
    let global_start_time = Instant::now();

    // 1. Generate a secret key.
    let sk = KeyGen::generate_secret_key(params, &mut thread_rng());
    println!("Secret Key Generation done!\n");

    // 2. Create Encryptor, Decryptor, and Compare (FBS) instances.
    let enc = Encryptor::new(&sk);
    let dec = Decryptor::new(&sk);
    let cmp = FheCompare::new(&sk, &mut thread_rng());
    println!("Evaluation Key Generation done!\n");
    println!("Initialized!");

    // A counter to track how many tests produced the correct MSB.
    let mut correct_predictions = 0;

    // 3. Run tests sequentially from 0..total_tests.
    for test_num in 1..(total_tests + 1) {
        let mut rng = thread_rng();
        let start_time = Instant::now();

        // Generate a random number in the range [0, 2^plain_modulus_bits).
        let i = rng.gen_range(0..(1u64 << plain_modulus_bits));

        // The expected MSB is the top bit of i.
        let expected: M = (i >> (plain_modulus_bits - 1)) & 1;

        // Encrypt the number using the provided modulus.
        let enc_text = enc.encrypt(i, modulus, &mut rng, plain_modulus_bits);

        // Perform homomorphic MSB extraction.
        let enc_extract: LweCiphertext<M> = cmp.hommsb::<M>(&enc_text, plain_modulus_bits);

        // Decrypt the extracted MSB (boolean result, so mod 2).
        let dec_extract = dec.decrypt_custom::<M>(&enc_extract, modulus, 1u32);

        let epoch_duration = start_time.elapsed();

        // Check correctness. Print detailed info for each test.
        if dec_extract == expected {
            correct_predictions += 1;
            println!(
                "Test #{:05}: m = {}, expected MSB = {}, extracted MSB = {} [OK] total time: {:?}",
                test_num, i, expected, dec_extract, epoch_duration
            );
        } else {
            println!(
                "Test #{:05}: m = {}, expected MSB = {}, extracted MSB = {} [ERROR] total time: {:?}",
                test_num, i, expected, dec_extract, epoch_duration
            );
        }
    }

    // 4. Calculate accuracy and display final statistics.
    let global_duration = global_start_time.elapsed();
    let accuracy = correct_predictions as f64 / total_tests as f64;

    println!(
        "Total tests: {}\nPlaintext bits: {} \nFinal Accuracy(MSB): {:.2}% \nTime Cost: {:?}",
        total_tests,
        plain_modulus_bits,
        accuracy * 100.0,
        global_duration
    );
}

/// This function performs a multi-threaded test to check the correctness
/// of extracting the Most Significant Bit (MSB) from a homomorphically
/// encrypted value. It uses Arc and Mutex to safely share state among threads,
/// and a progress bar mechanism to visualize test completion.
///
/// # Arguments
/// * `plain_modulus_bits` - The bit-size of the plaintext modulus range.
/// * `total_tests`        - The total number of tests to run.
/// * `params`             - The parameters used for key generation and encryption/decryption.
fn msb_multi_threaded_tests(
    plain_modulus_bits: u32,
    total_tests: u32,
    params: CmpFheParameters<M, LweModulus, Fp>,
) {
    // Set modulus to (q - 1) for BrMsKs (Bootstrap + Relinearization) mode conversion.
    let modulus = <PowOf2Modulus<M>>::new_with_mask(params.lwe_cipher_modulus_minus_one());

    // Start timing the entire test process.
    let global_start_time = Instant::now();

    // 1. Generate a secret key.
    let sk = KeyGen::generate_secret_key(params, &mut thread_rng());
    println!("Secret Key Generation done!\n");

    // 2. Create Encryptor, Decryptor, and compare (FBS) instances.
    let enc = Encryptor::new(&sk);
    let dec = Decryptor::new(&sk);
    let cmp = FheCompare::new(&sk, &mut thread_rng());
    println!("Evaluation Key Generation done!\n");
    println!("Initialized!");

    // Use Arc and Mutex to safely share state among threads.
    // 'output' will store messages about test errors for later processing.
    let output = Arc::new(Mutex::new(Vec::new()));

    // 'progress' stores the last test index that triggered a periodic accuracy update (every 10%).
    let progress = Arc::new(Mutex::new(0));

    // 'shared_var' tracks the count of completed tests, so we can compute a simple progress bar.
    let shared_var = Arc::new(Mutex::new(0));

    // 3. Run the tests in parallel using Rayon's parallel iterator.
    let results: Vec<_> = (1..(total_tests + 1))
        .into_par_iter()
        .map(|test_num| {
            let mut rng = thread_rng();

            // Generate a random plaintext number in the range of [0, 2^plain_modulus_bits).
            let i = rng.gen_range(0..(1u64 << plain_modulus_bits));

            // The expected MSB is the (plain_modulus_bits - 1)-th bit of i.
            let expected: M = (i >> (plain_modulus_bits - 1)) & 1;

            // Encrypt the number using the provided modulus.
            let enc_text = enc.encrypt(i, modulus, &mut rng, plain_modulus_bits);

            // Extract the MSB homomorphically.
            let enc_extract: LweCiphertext<M> = cmp.hommsb::<M>(&enc_text, plain_modulus_bits);

            // Decrypt the extracted ciphertext (MSB). For a boolean result, use mod 2.
            let dec_extract = dec.decrypt_custom::<M>(&enc_extract, modulus, 1u32);

            // Check whether the extracted MSB matches the expected MSB.
            let error_flag = dec_extract != expected;

            // Thread-safe access to the shared test counter.
            {
                let mut shared_var_lock = shared_var.lock().unwrap();
                *shared_var_lock += 1; // Increment the completed tests counter.

                // Compute progress percentage.
                let percentage = (*shared_var_lock as f64 / total_tests as f64) * 100.0;

                // Build a progress bar string of length 50 characters.
                let progress_bar_length = 50;
                let filled_length =
                    (percentage / 100.0 * progress_bar_length as f64).round() as usize;
                let progress_string = format!(
                    "[{}{}] {:.2}% ({}/{})",
                    "=".repeat(filled_length),
                    " ".repeat(progress_bar_length - filled_length),
                    percentage,
                    *shared_var_lock,
                    total_tests
                );

                // Clear the console and print the updated progress bar.
                print!("\x1b[2J\x1b[H");
                println!("Progress: {}", progress_string);
            }

            // Return the test result information for later aggregation.
            (test_num, error_flag, i, dec_extract, expected)
        })
        .collect();

    // 4. Process the results and print statistics.
    let mut correct_predictions = 0;

    for (test_num, error_flag, m, dec_extract, expected) in results {
        if error_flag {
            // If there's an error, store a diagnostic message in 'output'.
            let mut output_lock = output.lock().unwrap();
            output_lock.push(format!(
                "Test #{:05} [ERROR]: m = {}, expected MSB = {}, extracted MSB = {}",
                test_num, m, expected, dec_extract
            ));
        } else {
            correct_predictions += 1;
        }

        // Periodically show accuracy updates every 10% of total tests.
        if (test_num) % (total_tests / 10) == 0 && test_num != 0 {
            let accuracy = (correct_predictions as f64 / test_num as f64) * 100.0;
            let mut progress_lock = progress.lock().unwrap();
            *progress_lock = test_num;
            println!(
                "[Progress] After {} tests: accuracy = {:.2}%",
                *progress_lock, accuracy
            );
        }
    }

    // Measure and report the total elapsed time after all tests finish.
    let global_duration = global_start_time.elapsed();
    let final_accuracy = (correct_predictions as f64 / total_tests as f64) * 100.0;

    println!(
        "\nTotal tests: {}\nPlaintext bits: {}\nFinal Accuracy (MSB): {:.2}%\nTime Cost: {:?}\n",
        total_tests, plain_modulus_bits, final_accuracy, global_duration
    );
}

/// A single-threaded test function that compares two random plaintexts homomorphically.
/// It checks three types of comparisons (>, >=, ==) and calculates their accuracy.
///
/// # Arguments
/// - `plain_modulus_bits`: The bit size of the plaintext modulus range (we use `plain_modulus_bits - 1` for random generation).
/// - `total_tests`: The total number of comparison tests to run.
/// - `params`: The parameters used for generating the key and performing encryption/decryption.
fn cmp_single_threaded_tests(
    plain_modulus_bits: u32,
    total_tests: u32,
    params: CmpFheParameters<M, LweModulus, Fp>,
) {
    // Use q-1 as the modulus for BrMsKs (Bootstrap + Relinearization) mode conversion.
    let modulus = <PowOf2Modulus<M>>::new_with_mask(params.lwe_cipher_modulus_minus_one());
    // Start the global timer to measure total test duration.
    let global_start_time = Instant::now();

    // 1. Generate a secret key.
    let sk = KeyGen::generate_secret_key(params, &mut thread_rng());
    println!("Secret Key Generation done!\n");

    // 2. Create Encryptor, Decryptor, and fhe_compare instances.
    let enc = Encryptor::new(&sk);
    let dec = Decryptor::new(&sk);
    let cmp = FheCompare::new(&sk, &mut thread_rng());
    println!("Evaluation Key Generation done!\n");
    println!("Initialized!");

    // Counters for correct comparisons of each type.
    let mut correct_count_greater = 0;
    let mut correct_count_greater_equal = 0;
    let mut correct_count_equal = 0;

    // 3. Run the tests for the specified number of iterations.
    for i in 1..=total_tests {
        let mut rng = thread_rng();
        let start_time = Instant::now();

        // Generate two random plaintexts (m1, m2) in range [0, 2^(plain_modulus_bits-1)).
        // This ensures the plaintext bits is effectively one bit more than needed.
        let m_1: u64 = rng.gen_range(0..(1 << (plain_modulus_bits - 1)));
        let m_2: u64 = rng.gen_range(0..(1 << (plain_modulus_bits - 1)));

        // Determine the expected results for the three comparisons.
        let expected_greater: M = if m_1 > m_2 { 1u64 } else { 0u64 }.as_into();
        let expected_greater_equal: M = if m_1 >= m_2 { 1u64 } else { 0u64 }.as_into();
        let expected_equal: M = if m_1 == m_2 { 1u64 } else { 0u64 }.as_into();

        // Encrypt the plaintexts using the given modulus.
        let enc_text_1 = enc.encrypt(m_1, modulus, &mut rng, plain_modulus_bits);
        let enc_text_2 = enc.encrypt(m_2, modulus, &mut rng, plain_modulus_bits);

        // Perform homomorphic comparisons.
        let greater_enc = cmp.greater_than::<M>(&enc_text_1, &enc_text_2, plain_modulus_bits);
        let greater_equal_enc =
            cmp.greater_than_equal::<M>(&enc_text_1, &enc_text_2, plain_modulus_bits);
        let equal_enc = cmp.equal::<M>(&enc_text_1, &enc_text_2, plain_modulus_bits);

        // Decrypt the comparison results (boolean results mod 2).
        let dec_greater = dec.decrypt_custom::<M>(&greater_enc, modulus, 1u32);
        let dec_greater_equal = dec.decrypt_custom::<M>(&greater_equal_enc, modulus, 1u32);
        let dec_equal = dec.decrypt_custom::<M>(&equal_enc, modulus, 1u32);

        // Measure the time taken for this single iteration.
        let epoch_duration = start_time.elapsed();

        // Update correctness counters. If a comparison is correct, increment the counter.
        let mut error_flag = false;
        if dec_greater == expected_greater {
            correct_count_greater += 1;
        } else {
            error_flag = true;
        }

        if dec_greater_equal == expected_greater_equal {
            correct_count_greater_equal += 1;
        } else {
            error_flag = true;
        }

        if dec_equal == expected_equal {
            correct_count_equal += 1;
        } else {
            error_flag = true;
        }

        // Print a detailed error or success message for each test.
        if error_flag {
            println!(
                "Test #{:05}: m1 = {}, m2 = {} \
                 | >? decrypted = {}, expected = {} \
                 | >=? decrypted = {}, expected = {} \
                 | ==? decrypted = {}, expected = {} \
                 [ERROR] total time: {:?}",
                i,
                m_1,
                m_2,
                dec_greater,
                expected_greater,
                dec_greater_equal,
                expected_greater_equal,
                dec_equal,
                expected_equal,
                epoch_duration
            );
        } else {
            println!(
                "Test #{:05}: m1 = {}, m2 = {} | [OK] total time: {:?}",
                i, m_1, m_2, epoch_duration
            );
        }

        // Print accuracy every 10% of the total tests, to track progress.
        if i % (total_tests / 10) == 0 {
            let acc_g = (correct_count_greater as f64 / i as f64) * 100.0;
            let acc_ge = (correct_count_greater_equal as f64 / i as f64) * 100.0;
            let acc_e = (correct_count_equal as f64 / i as f64) * 100.0;

            println!(
                "[Progress] After {} tests: \
                 accuracy(>) = {:.2}%, (>=) = {:.2}%, (==) = {:.2}%",
                i, acc_g, acc_ge, acc_e
            );
        }
    }

    // After completing all tests, measure total elapsed time.
    let global_duration = global_start_time.elapsed();

    // Calculate final accuracy for each type of comparison.
    let accuracy_g = (correct_count_greater as f64 / total_tests as f64) * 100.0;
    let accuracy_ge = (correct_count_greater_equal as f64 / total_tests as f64) * 100.0;
    let accuracy_e = (correct_count_equal as f64 / total_tests as f64) * 100.0;

    // Print the final accuracy of each comparison, along with the total execution time.
    println!(
        "Total tests: {} \n Plaintext bits: {}\n
         Accuracy(>) = {:.2}%, (>=) = {:.2}%, (==) = {:.2}%\n
         Time Cost: {:?}",
        total_tests, plain_modulus_bits, accuracy_g, accuracy_ge, accuracy_e, global_duration
    );
}

/// A multi-threaded function that tests three comparison operations
/// (>, >=, ==) homomorphically. It spawns parallel tasks
/// to encrypt pairs of random plaintexts, perform each comparison,
/// and record correctness.
///
/// # Arguments
/// * `plain_modulus_bits` - The bit-size of the plaintext modulus (note the
///   random values are generated using `plain_modulus_bits - 1`).
/// * `total_tests`        - The total number of random tests to run.
/// * `params`             - Parameters for key generation, encryption, etc.
fn cmp_multi_threaded_tests(
    plain_modulus_bits: u32,
    total_tests: u32,
    params: CmpFheParameters<M, LweModulus, Fp>,
) {
    // 1. Prepare modulus for BrMsKs mode conversion.
    let modulus = <PowOf2Modulus<M>>::new_with_mask(params.lwe_cipher_modulus_minus_one());

    // Start measuring total execution time.
    let global_start_time = Instant::now();

    // 2. Generate a secret key.
    let sk = KeyGen::generate_secret_key(params, &mut thread_rng());
    println!("Secret Key Generation done!\n");

    // 3. Create Encryptor, Decryptor, and comparison instances.
    let enc = Encryptor::new(&sk);
    let dec = Decryptor::new(&sk);
    let cmp = FheCompare::new(&sk, &mut thread_rng());
    println!("Evaluation Key Generation done!\n");
    println!("Initialized!");

    // Shared state for collecting only error outputs and tracking progress.
    let output = Arc::new(Mutex::new(Vec::new()));
    let progress = Arc::new(Mutex::new(0));
    let shared_var = Arc::new(Mutex::new(0));

    // 4. Run tests in parallel using Rayon.
    let results: Vec<_> = (1..=total_tests)
        .into_par_iter()
        .map(|test_idx| {
            let mut rng = thread_rng();

            // Generate two random plaintexts in [0, 2^(plain_modulus_bits - 1)).
            let (m_1, m_2) = {
                let a = rng.gen_range(0..(1 << (plain_modulus_bits - 1)));
                let b = rng.gen_range(0..(1 << (plain_modulus_bits - 1)));
                (a, b)
            };

            // Determine the expected results for three comparisons.
            let expected_greater: M = if m_1 > m_2 { 1u64 } else { 0u64 }.as_into();
            let expected_greater_equal: M = if m_1 >= m_2 { 1u64 } else { 0u64 }.as_into();
            let expected_equal: M = if m_1 == m_2 { 1u64 } else { 0u64 }.as_into();

            // Encrypt both plaintexts.
            let enc_text_1 = enc.encrypt(m_1, modulus, &mut rng, plain_modulus_bits);
            let enc_text_2 = enc.encrypt(m_2, modulus, &mut rng, plain_modulus_bits);

            // Perform homomorphic comparisons.
            let enc_g = cmp.greater_than::<M>(&enc_text_1, &enc_text_2, plain_modulus_bits);
            let enc_ge = cmp.greater_than_equal::<M>(&enc_text_1, &enc_text_2, plain_modulus_bits);
            let enc_eq = cmp.equal::<M>(&enc_text_1, &enc_text_2, plain_modulus_bits);

            // Decrypt results (mod 1 => boolean).
            let dec_g = dec.decrypt_custom::<u64>(&enc_g, modulus, 1);
            let dec_ge = dec.decrypt_custom::<u64>(&enc_ge, modulus, 1);
            let dec_eq = dec.decrypt_custom::<u64>(&enc_eq, modulus, 1);

            // Compare decrypted values to the expected results.
            let error_flag_g = dec_g != expected_greater;
            let error_flag_ge = dec_ge != expected_greater_equal;
            let error_flag_eq = dec_eq != expected_equal;

            // Update shared test counter for progress bar.
            {
                let mut shared_var_lock = shared_var.lock().unwrap();
                *shared_var_lock += 1;
                let percentage = (*shared_var_lock as f64 / total_tests as f64) * 100.0;

                let progress_bar_length = 50;
                let filled_length =
                    (percentage / 100.0 * progress_bar_length as f64).round() as usize;

                let progress_str = format!(
                    "[{}{}] {:.2}%({}/{})",
                    "=".repeat(filled_length),
                    " ".repeat(progress_bar_length - filled_length),
                    percentage,
                    *shared_var_lock,
                    total_tests
                );

                // Clear the console and show the updated progress bar.
                print!("\x1b[2J\x1b[H");
                println!("Progress: {}", progress_str);
            }

            // Return this test's outcomes.
            (
                test_idx,
                m_1,
                m_2,
                dec_g,
                expected_greater,
                error_flag_g,
                dec_ge,
                expected_greater_equal,
                error_flag_ge,
                dec_eq,
                expected_equal,
                error_flag_eq,
            )
        })
        .collect();

    // 5. Aggregate results. We maintain correctness counters for each comparison.
    let mut correct_count_g = 0;
    let mut correct_count_ge = 0;
    let mut correct_count_eq = 0;

    // Only push error lines into the shared output vector.
    for (
        test_idx,
        m_1,
        m_2,
        dec_g,
        expected_g,
        error_flag_g,
        dec_ge,
        expected_ge,
        error_flag_ge,
        dec_eq,
        expected_eq,
        error_flag_eq,
    ) in results
    {
        if !error_flag_g {
            correct_count_g += 1;
        }
        if !error_flag_ge {
            correct_count_ge += 1;
        }
        if !error_flag_eq {
            correct_count_eq += 1;
        }

        // If any comparison was incorrect, we store its info.
        if error_flag_g || error_flag_ge || error_flag_eq {
            let mut message = format!("Test #{:05}: m1 = {}, m2 = {} | ", test_idx, m_1, m_2);

            if error_flag_g {
                message.push_str(&format!(">? dec={}, exp={} [ERR]", dec_g, expected_g));
            }
            if error_flag_ge {
                message.push_str(&format!(" >=? dec={}, exp={} [ERR]", dec_ge, expected_ge));
            }
            if error_flag_eq {
                message.push_str(&format!(" ==? dec={}, exp={} [ERR]", dec_eq, expected_eq));
            }
            message.push_str(" [ERROR]");

            let mut output_vec = output.lock().unwrap();
            output_vec.push(message);
        }

        // Display progress every 10% of total tests (informative output only).
        if test_idx % (total_tests / 10) == 0 {
            let mut progress_lock = progress.lock().unwrap();
            *progress_lock = test_idx;

            let curr_acc_g = correct_count_g as f64 / test_idx as f64 * 100.0;
            let curr_acc_ge = correct_count_ge as f64 / test_idx as f64 * 100.0;
            let curr_acc_eq = correct_count_eq as f64 / test_idx as f64 * 100.0;

            println!(
                "[Progress] After {} tests:\n  \
                   Accuracy(>) = {:.2}%, (>=) = {:.2}%, (==) = {:.2}%",
                *progress_lock, curr_acc_g, curr_acc_ge, curr_acc_eq
            );
        }
    }

    // 6. Print all stored error lines.
    {
        let output_lock = output.lock().unwrap();
        println!("\n===== Error Logs (if any) =====");
        for line in output_lock.iter() {
            println!("{}", line);
        }
    }

    // Compute and print the final statistics for each comparison.
    let global_duration = global_start_time.elapsed();
    let final_acc_g = correct_count_g as f64 / total_tests as f64 * 100.0;
    let final_acc_ge = correct_count_ge as f64 / total_tests as f64 * 100.0;
    let final_acc_eq = correct_count_eq as f64 / total_tests as f64 * 100.0;

    println!(
        "\n===== Final Statistics =====\n\
         Total tests: {} \nPlaintext bits: {}\n
         Accuracy(>) = {:.2}%, (>=) = {:.2}%, (==) = {:.2}% \n
         Time Cost: {:?}",
        total_tests, plain_modulus_bits, final_acc_g, final_acc_ge, final_acc_eq, global_duration
    );
}
