# ThFHE: Threshold Fully Homomorphic Encryption System

This guide walks you through setting up our **ThFHE** implementation, compiling the necessary components, and running threshold key generation and decryption experiments.

---

##  Installation

Install required dependencies:

```bash
sudo apt update
sudo apt install -y curl wget python3 python3-pip build-essential iproute2 git cmake
```

Install Rust:

```bash
echo "Installing Rust..."
curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"
```

Install EMP-Toolkit (required for Beaver triple generation):

```bash
echo "Installing emp-toolkit..."
wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python3 install.py --install --tool --ot
```


---
##  Running Key Generation and Threshold Decryption

Enter the project directory:

```bash
cd thfhe_code/
```

Copy the multi-process execution script:

```bash
cp thfhe/batch/multiprocess-run-thfhe.py ./
```

Ensure that **Rust**, **Cargo**, and **Python** are properly installed:

```bash
cargo -V
python3 -V
```

Build the binary (ensure you're inside `code/`):

```bash
cargo build --package thfhe --example thfhe --release
```

Run multi-process ThFHE decryption:

```bash
python3 multiprocess-run-thfhe.py <NUM_PARTIES> <BASE_PORT> <BANDWIDTH_MBPS> <DELAY_MS>
```

For example:

```bash
python3 multiprocess-run-thfhe.py 3 10000 1000 0
```

This launches a 3-party ThFHE decryption using ports starting from `10000`, with a bandwidth cap of 1000 Mbps and 0 ms network delay.

To support network throttling and latency simulation, install:

```bash
sudo apt install iputils-ping iptables net-tools
```

>  These tools might not work in virtualized or containerized environments, which may prevent bandwidth/latency control from functioning.

---

##  Beaver Triple Generation for Z₂ᵏ

By default, only a small set of Beaver triples over 𝑍₂ᵏ are generated for testing. To generate new triples:

1. Copy the multi-process script:

   ```bash
   cp thfhe/batch/multiprocess-run-triples.py thfhe/triples/
   ```

2. Build the C++ triple generator:

   ```bash
   cd thfhe/triples/
   mkdir build && cd build
   cmake ..
   make
   cp bin/test_triples ../test_triples
   cd ..
   ```

3. Run the triple generation script:

   ```bash
   python3 multiprocess-run-triples.py <NUM_PARTIES> <BASE_PORT> <BANDWIDTH_MBPS> <DELAY_MS>
   ```

   Example:

   ```bash
   python3 multiprocess-run-triples.py 3 10000 10000 0
   ```

   This generates Beaver triples for 3 parties over 𝑍₂⁶⁴. The generated triples will be saved under `thfhe/triples/data/`.

4. To use these triples for decryption, copy them to the corresponding folder:

   ```bash
   mkdir ../predata/5/
   cp data/triples* ../predata/5/
   ```

   During distributed decryption, each party will read its triple from:

   ```
   thfhe/predata/{NUM_PARTIES}/triples_P_{party_id}.txt
   ```

---

##  Multi-Instance Deployment

If you run the system across multiple machines, update the IP list in:

```
thfhe/batch/iplist/ip.txt
```

Add one line per party's IP address to enable peer-to-peer connections.

---

##  Configuration Notes

- **Triple count**: Default is 1 million triples. To change this, modify the `num_triples` constant in:

  ```
  thfhe/triples/test/triples.cpp
  ```

- **Decryption batch sizes**: The default batch sizes are `[1, 10, 100, 1000, 20000]`. To modify, change the `test_total_num` variable in:

  ```
  thfhe/examples/thfhe.rs
  ```

- **Computation inputs**: The default plaintext computation is `a + b`. You can change `a` and `b` inside:

  ```
  thfhe/examples/thfhe.rs
  ```

  >  The plaintext modulus is 4.

---

##  Project Structure

- `thfhe/src/`: Core ThFHE protocol implementation  
- `mpc/src/`: MPC schemes (e.g., Shamir and additive secret sharing)  
- `network/src/`: Basic network communication I/O  
- `fhe_core/src/`: Underlying TFHE core logic  
