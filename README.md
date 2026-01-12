# Hekaton SHA256 Benchmark

This repository contains a SHA256 benchmarking circuit implementation for the [Hekaton](https://github.com/Pratyush/hekaton-system) horizontally-scalable zkSNARK system.

## Overview

This project implements a SHA256 circuit that can be partitioned into multiple subcircuits for distributed proving. It measures the performance of SHA256 operations in the Hekaton system, including:

- **Setup time**:  Proving key generation
- **Stage 0 (Commitment)**: Computing commitments to subcircuit witnesses  
- **Stage 1 (Proving)**: Generating Groth16 proofs for each subcircuit
- **Aggregation**: Aggregating all subcircuit proofs into a single proof
- **Verification**: Verifying the aggregated proof

## Project Structure

```
├── distributed-prover/
│   └── src/
│       ├── sha256_bench_circuit.rs    # SHA256 benchmark circuit implementation
│       ├── bin/
│       │   └── sha256_benchmark.rs    # Benchmark binary
│       └── coordinator. rs             # Modified to expose public_inputs
├── cp-groth16/                        # Commit-and-prove Groth16 implementation
├── mpi-snark/                         # MPI distributed prover
└── slurm_scripts/                     # Cluster scripts
```

## Requirements

- **Rust**:  1.70+ (with nightly toolchain recommended)
- **Memory**: 4GB+ RAM (16GB+ recommended for larger configurations)
- **OS**: Linux (tested on Ubuntu 22.04)

## Installation

```bash
# Clone the repository
git clone https://github.com/Entropy-pp/hekaton_sha256.git
cd hekaton_sha256

# Build in release mode
cargo build --release
```

## Running the Benchmark

### Quick Test

```bash
cargo run -p distributed-prover --release --bin sha256_benchmark
```

### Run Unit Tests

```bash
# Run SHA256 circuit tests
cargo test -p distributed-prover sha256_bench

# Run all tests
cargo test --release
```

## Configuration

You can modify the benchmark configurations in `distributed-prover/src/bin/sha256_benchmark.rs`:

```rust
let configs:  Vec<Sha256BenchCircuitParams> = vec![
    // Small configurations (quick testing)
    Sha256BenchCircuitParams {
        num_subcircuits: 2,              // Must be power of 2 and > 1
        num_sha_iters_per_subcircuit: 1, // Must be >= 1
    },
    Sha256BenchCircuitParams {
        num_subcircuits:  4,
        num_sha_iters_per_subcircuit: 2,
    },
    // Add more configurations as needed... 
];
```

### Parameter Descriptions

| Parameter | Description | Requirements |
|-----------|-------------|--------------|
| `num_subcircuits` | Number of subcircuits for parallel proving | Must be power of 2, > 1 |
| `num_sha_iters_per_subcircuit` | SHA256 iterations per subcircuit | Must be ≥ 1 |

### Example Configurations

| Config | Constraints | Est. Memory | Est. Time |
|--------|-------------|-------------|-----------|
| nc=2, ns=1 | ~150K | ~2 GB | ~1 min |
| nc=4, ns=2 | ~460K | ~4 GB | ~3 min |
| nc=8, ns=4 | ~1.5M | ~8 GB | ~10 min |
| nc=16, ns=4 | ~3M | ~16 GB | ~20 min |

## Output Example

```
================================================================================
                        Hekaton SHA256 Circuit Benchmark
================================================================================

>>> Running benchmark for 4 subcircuits, 2 SHA256 iterations each... 
  [1/5] Setup:   Generating proving keys...
       Setup completed in 45678. 90ms
  [2/5] Stage 0: Computing commitments...
       Stage 0 completed in 1234.56ms
  [3/5] Stage 1: Generating proofs...
       Stage 1 completed in 5678.90ms
  [4/5] Aggregating proofs...
       Aggregation completed in 890.12ms
  [5/5] Verifying proof...
       Verification completed in 12. 34ms (VALID)

==============================================================================
                     SHA256 Circuit Benchmark Results
==============================================================================
    NC     NS  Constraints   Setup(ms)   Stage0(ms)  Stage1(ms)   Total(ms)
------------------------------------------------------------------------------
     4      2       456000     45678.90      1234.56     5678.90     7803.58
```

## Circuit Architecture

The SHA256 benchmark circuit uses a **chained hash structure**:

```
┌─────────────────┐  portal   ┌─────────────────┐  portal   ┌─────────────────┐
│  Subcircuit 0   │ ────────► │  Subcircuit 1   │ ────────► │  Subcircuit N-1 │
│                 │  hash_0   │                 │  hash_1   │                 │
│ SHA256(input_0) │           │ SHA256(hash_0   │           │ SHA256(hash_n-2 │
│      × N iters  │           │   || input_1)   │           │   || input_n-1) │
│                 │           │      × N iters  │           │   + verify      │
└─────────────────┘           └─────────────────┘           └─────────────────┘
```

- **Subcircuit 0**: Hashes the initial 64-byte input
- **Subcircuit 1 to N-2**: Combines previous hash with current input via portal wires
- **Subcircuit N-1**: Final hash computation with verification against expected output

## Constraint Breakdown

Each subcircuit's constraints come from: 

| Component | Approx. Constraints |
|-----------|---------------------|
| SHA256 ZK circuit (per iteration) | ~27,000 |
| Portal GET operation | ~480 |
| Portal SET operation | ~480 |
| Digest conversion | ~512 |
| Final verification (last only) | ~256 |

**Formula:**
```
Total ≈ num_subcircuits × (num_sha_iters × 27,000 + portal_overhead)
```

## Key Files

- **`sha256_bench_circuit.rs`**: Core circuit implementation with `CircuitWithPortals` trait
- **`sha256_benchmark.rs`**: Benchmark runner with timing and metrics collection
- **`coordinator.rs`**: Modified to expose `get_public_inputs()` for verification

## License

This project is licensed under MIT/Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Acknowledgments

Based on the [Hekaton](https://github.com/Pratyush/hekaton-system) system by Pratyush Mishra et al. 

## References

- [Hekaton:  Horizontally-Scalable zkSNARKs via Proof Aggregation](https://eprint.iacr.org/2024/XXX)
- [arkworks](https://github.com/arkworks-rs) - Rust ecosystem for zkSNARKs