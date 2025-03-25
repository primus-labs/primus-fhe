# Homomorphic MSB Extraction and Comparison Tests

This repository demonstrates how to **homomorphically** extract the most significant bit (MSB) of encrypted integers and perform homomorphic comparisons (>, >=, ==) using a TFHE-like scheme. It leverages:

- **Rayon** for multi-threaded parallelism.
- **Arc** and **Mutex** from the standard library for thread-safe data sharing.

Below is a brief explanation of each major part of the code, details on running it, and the bit-range limitations.

------

## Table of Contents

1. [Overview](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#overview)
2. [Key Components](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#key-components)
3. [Bit Range Limitations](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#bit-range-limitations)
4. [Running the Tests](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#running-the-tests)
5. [Single-Threaded vs Multi-Threaded](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#single-threaded-vs-multi-threaded)
6. [Interpreting the Output](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#interpreting-the-output)
7. [Dependencies](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#dependencies)

------

## Overview

The code tests two main functionalities:

1. **Homomorphic MSB Extraction**
    Given an integer $m$ encrypted under a TFHE-like scheme, this operation returns the integer’s most significant bit – still in encrypted form. For instance, if $m$ is within 5 bits $[0, 2^5)$, extracting its MSB would yield whether $m$ is in the top half of that range $(16 \dots 31$ in cleartext).
2. **Homomorphic Comparison**
    Comparisons such as $m1 > m2$, $m1 >= m2$, and $m1 == m2$ are performed directly on encrypted data, yielding an encrypted boolean result. Decrypting that result indicates whether the relationship is true or false without revealing the cleartext of $m1$ or $m2$.

These tests verify the correctness and performance of those operations under various parameter settings.

------

## Key Components

1. **`KeyGen::generate_secret_key`**
    Creates a secret key for both LWE encryption and bootstrapping.
2. **`Encryptor` and `Decryptor`**
   - **Encryptor**: Encrypts plaintext integers into LWE ciphertexts using the secret key.
   - **Decryptor**: Decrypts LWE ciphertexts back to plaintext integers.
3. **`FheCompare`**
    Provides methods for comparisons and the specialized MSB extraction. Internally, it uses TFHE-like bootstrapping techniques to evaluate these operations on ciphertexts.
4. **MSB Extraction Functions**
   - **Single-threaded**: `msb_single_threaded_tests`
   - **Multi-threaded**: `msb_multi_threaded_tests`
      Both functions encrypt random values, homomorphically extract their MSB, decrypt, and then verify correctness.
5. **Comparison Functions**
   - **Single-threaded**: `cmp_single_threaded_tests`
   - **Multi-threaded**: `cmp_multi_threaded_tests`
      Perform $*>, >=, ==*$ comparisons of random pairs of plaintexts under encryption, then decrypt to check correctness.
6. **Thread Safety**
    Uses **`Arc<Mutex<T>>`** to maintain safe shared counters and progress indicators across threads.
7. **Progress Tracking**
   - **Single-threaded**: Prints results as it iterates through tests.
   - **Multi-threaded**: Uses a simple text-based progress bar, updated every time a thread finishes a test.

------

## Bit Range Limitations

- The code **supports up to 33-bit** plaintexts for MSB extraction.
- When running in **33-bit mode**, the MSB extraction process operates on a *33-bit* range.
- **Comparisons** (>, >=, ==) currently handle a *32-bit* range, even when using 33 bits for MSB extraction.

Hence, if you enable 33-bit operation for MSB extraction, be aware that comparisons are effectively capped at 32 bits in this implementation.

------

## Running the Tests

1. **Clone or Download** this repository (or place the code in a Rust project environment).

2. **Ensure Dependencies** are met (see the [Dependencies](https://chatgpt.com/c/67e10660-44a0-800a-83dd-84a567944cd5#dependencies) section).

3. Build and Run

    the project:

   ```bash
   cargo run --release --example fhe_hmsb
   ```

   By default, the code sets:

   ```rust
   let plain_modulus_bits: u32 = 5;  // Example bit size for plaintext range
   let total_tests: u32 = 100;       // Number of tests to run
   let if_run_thread: bool = true;   // Use multi-threaded tests if true
   ```

------

## Single-Threaded vs Multi-Threaded

- **Single-threaded** functions (`msb_single_threaded_tests`, `cmp_single_threaded_tests`) run each test sequentially on one thread.
- **Multi-threaded** functions (`msb_multi_threaded_tests`, `cmp_multi_threaded_tests`) divide tests among available CPU cores via **Rayon**, giving faster overall completion on multi-core machines.

You can toggle the mode by changing:

```rust
let if_run_thread: bool = true;  // or false for single-threaded
//below average times
```

------

## Interpreting the Output

1. **Progress Bar** (Multi-threaded Mode):
    Displays a running percentage of completed tests with a simple bar visualization.
2. **Result Logs**:
   - **`[OK]`** indicates a test that passed verification.
   - **`[ERROR]`** is reported for any mismatch between the decrypted output and the expected value.
3. **Accuracy**:
    Printed at the end of each test batch. Shows the percentage of correct operations for MSB extraction or for each comparison type (>, >=, ==).
4. **Time Cost**:
    Measures how long the entire test run took, giving an idea of performance.

------

## Dependencies

The code relies on the following crates:

- [**rand**](https://crates.io/crates/rand) – for random number generation.
- [**rayon**](https://crates.io/crates/rayon) – for parallel iterations and multi-threaded functionality.
- **fhe_cmp**– (Local or custom) TFHE-based homomorphic comparison primitives.
- **fhe_core**– (Local or custom) core cryptographic data structures and TFHE methods.
- **algebra**– (Local or custom) numeric types, field operations, and polynomial arithmetic for TFHE.

Ensure you have these dependencies in your **`Cargo.toml`** or local environment:

```toml
# The following are placeholders for actual crate versions:
fhe_cmp = { path = "../fhe_cmp" }
fhe_core = { path = "../fhe_core" }
algebra = { path = "../algebra" }
```