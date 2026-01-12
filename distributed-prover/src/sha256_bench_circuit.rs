//! A simple SHA256 benchmarking circuit for the Hekaton system.
//!  This circuit performs repeated SHA256 hashing operations to measure performance.

use crate::{
    portal_manager::{PortalManager, RomProverPortalManager, SetupRomPortalManager},
    transcript::{MemType, TranscriptEntry},
    CircuitWithPortals,
};

use crate::vkd::util::*;
use crate::vkd::{InnerHash, INNER_HASH_SIZE};
use ark_crypto_primitives::crh::sha256::{
    constraints::{DigestVar, Sha256Gadget},
    digest::Digest,
    Sha256,
};
use ark_ff:: PrimeField;
use ark_r1cs_std::{alloc::AllocVar, bits::uint8::UInt8, eq::EqGadget, fields::fp::FpVar};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;

/// Input block size for SHA256 (64 bytes)
pub const SHA256_BLOCK_SIZE: usize = 64;

/// A circuit that benchmarks SHA256 performance by computing iterated hashes
/// across multiple subcircuits connected via portal wires.
#[derive(Clone)]
pub struct Sha256BenchCircuit {
    /// Initial input data for each subcircuit
    pub inputs: Vec<[u8; SHA256_BLOCK_SIZE]>,
    /// Expected final hash output
    pub final_hash: InnerHash,
    /// Circuit parameters
    pub params:  Sha256BenchCircuitParams,
}

/// Parameters that define the SHA256 benchmark circuit
#[derive(Copy, Clone, CanonicalSerialize, CanonicalDeserialize, Debug, PartialEq, Eq, Hash)]
pub struct Sha256BenchCircuitParams {
    /// Number of subcircuits (must be a power of 2 and > 1)
    pub num_subcircuits: usize,
    /// Number of SHA256 iterations per subcircuit
    pub num_sha_iters_per_subcircuit: usize,
}

impl std::fmt::Display for Sha256BenchCircuitParams {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "[nc={},ns={}]",
            self.num_subcircuits, self.num_sha_iters_per_subcircuit
        )
    }
}

impl Sha256BenchCircuit {
    /// Helper function:  Runs SHA256 over the input `num_iterations` times in ZK
    fn iterated_sha256_zk<F: PrimeField>(
        input: &[UInt8<F>],
        num_iterations: usize,
    ) -> Result<DigestVar<F>, SynthesisError> {
        let mut digest = Sha256Gadget:: digest(input)?;
        for _ in 1..num_iterations {
            digest = Sha256Gadget:: digest(&digest. 0)?;
        }
        Ok(digest)
    }

    /// Helper function: Runs SHA256 over the input `num_iterations` times natively
    fn iterated_sha256_native(input: &[u8], num_iterations: usize) -> [u8; 32] {
        let mut digest = Sha256:: digest(input).to_vec();
        for _ in 1..num_iterations {
            digest = Sha256::digest(&digest).to_vec();
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        result
    }

    /// Compute the expected final hash by chaining all subcircuits
    /// This must match exactly what generate_constraints does
    fn compute_final_hash(inputs: &[[u8; SHA256_BLOCK_SIZE]], num_sha_iters: usize) -> InnerHash {
        // First subcircuit: hash the full 64-byte input
        let mut prev_hash = Self::iterated_sha256_native(&inputs[0], num_sha_iters);

        // Subsequent subcircuits:  combine prev_hash (truncated) with first 32 bytes of input
        for input in inputs.iter().skip(1) {
            // Portal stores truncated hash (INNER_HASH_SIZE bytes), pad back to 32 bytes
            let mut prev_truncated = [0u8; 32];
            prev_truncated[..INNER_HASH_SIZE].copy_from_slice(&prev_hash[.. INNER_HASH_SIZE]);

            let mut combined = [0u8; 64];
            combined[..32]. copy_from_slice(&prev_truncated);
            combined[32..].copy_from_slice(&input[..32]);
            prev_hash = Self::iterated_sha256_native(&combined, num_sha_iters);
        }

        let mut result = [0u8; INNER_HASH_SIZE];
        result.copy_from_slice(&prev_hash[..INNER_HASH_SIZE]);
        result
    }
}

impl<F: PrimeField> CircuitWithPortals<F> for Sha256BenchCircuit {
    type Parameters = Sha256BenchCircuitParams;
    type ProverPortalManager = RomProverPortalManager<F>;
    const MEM_TYPE: MemType = MemType::Rom;

    fn num_subcircuits(&self) -> usize {
        self.params.num_subcircuits
    }

    /// Returns indices of unique subcircuits for CRS generation
    fn get_unique_subcircuits(&self) -> Vec<usize> {
        // First subcircuit is unique (no input from portal)
        // Last subcircuit is unique (has final verification)
        // Middle subcircuits are all the same
        if self.params.num_subcircuits == 2 {
            vec![0, 1]
        } else {
            vec![0, 1, self.params.num_subcircuits - 1]
        }
    }

    /// Maps a subcircuit index to its representative
    fn representative_subcircuit(&self, subcircuit_idx: usize) -> usize {
        let n = self.params.num_subcircuits;
        if subcircuit_idx == 0 {
            0
        } else if subcircuit_idx == n - 1 {
            n - 1
        } else {
            1
        }
    }

    fn get_params(&self) -> Sha256BenchCircuitParams {
        self.params
    }

    /// Creates a random instance of this circuit
    fn rand(rng: &mut impl Rng, params: &Sha256BenchCircuitParams) -> Self {
        let mut inputs = vec! [[0u8; SHA256_BLOCK_SIZE]; params.num_subcircuits];
        for input in inputs.iter_mut() {
            rng.fill(input);
        }
        let final_hash = Self::compute_final_hash(&inputs, params.num_sha_iters_per_subcircuit);

        Sha256BenchCircuit {
            inputs,
            final_hash,
            params: *params,
        }
    }

    /// Creates an empty circuit with given parameters
    fn new(params:  &Self::Parameters) -> Self {
        assert!(
            params.num_subcircuits. is_power_of_two(),
            "num_subcircuits must be a power of 2"
        );
        assert!(params.num_subcircuits > 1, "num_subcircuits must be > 1");
        assert!(
            params.num_sha_iters_per_subcircuit > 0,
            "num_sha_iters_per_subcircuit must be > 0"
        );

        Sha256BenchCircuit {
            inputs: vec! [[0u8; SHA256_BLOCK_SIZE]; params.num_subcircuits],
            final_hash: InnerHash::default(),
            params: *params,
        }
    }

    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        self.inputs[subcircuit_idx]
            .serialize_uncompressed(&mut buf)
            .unwrap();

        if subcircuit_idx == self.params.num_subcircuits - 1 {
            self.final_hash.serialize_uncompressed(&mut buf).unwrap();
        }
        buf
    }

    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        self.inputs[subcircuit_idx] =
            <[u8; SHA256_BLOCK_SIZE]>::deserialize_uncompressed_unchecked(
                &bytes[..SHA256_BLOCK_SIZE],
            )
            .unwrap();

        if subcircuit_idx == self.params.num_subcircuits - 1 && bytes.len() > SHA256_BLOCK_SIZE {
            self.final_hash =
                InnerHash::deserialize_uncompressed_unchecked(&bytes[SHA256_BLOCK_SIZE..]).unwrap();
        }
    }

    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError> {
        let num_iters = self.params.num_sha_iters_per_subcircuit;
        let is_first = subcircuit_idx == 0;
        let is_last = subcircuit_idx == self. params.num_subcircuits - 1;

        // Witness the input for this subcircuit
        let input_var = UInt8::new_witness_vec(ns!(cs, "input"), &self.inputs[subcircuit_idx])?;

        let digest = if is_first {
            // First subcircuit: hash the full 64-byte input
            Self::iterated_sha256_zk(&input_var, num_iters)?
        } else {
            // Subsequent subcircuits: get previous hash and combine with first 32 bytes of input
            let prev_hash_fp = pm.get(&format!("hash_{}", subcircuit_idx - 1))?;
            let prev_hash_bytes = fpvar_to_digest(&prev_hash_fp)?;

            let mut padded_prev:  Vec<UInt8<F>> = prev_hash_bytes;
            while padded_prev.len() < 32 {
                padded_prev.push(UInt8::constant(0u8));
            }

            let combined:  Vec<UInt8<F>> = padded_prev
                .into_iter()
                .chain(input_var.into_iter().take(32))
                .collect();

            Self::iterated_sha256_zk(&combined, num_iters)?
        };

        let hash_result = digest_to_fpvar(digest)?;

        // Store the hash result in portal manager
        pm.set(format!("hash_{}", subcircuit_idx), &hash_result)?;

        // For the last subcircuit, verify against expected final hash
        if is_last {
            let expected_hash_fp = F::from_le_bytes_mod_order(&self.final_hash);
            let expected_var =
                FpVar::new_witness(ns!(cs, "expected_hash"), || Ok(expected_hash_fp))?;
            hash_result.enforce_equal(&expected_var)?;
        }

        Ok(())
    }

    fn get_portal_subtraces(&self) -> Vec<Vec<TranscriptEntry<F>>> {
        let cs:  ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let mut pm = SetupRomPortalManager::<F>::new(cs.clone());
        let num_iters = self.params.num_sha_iters_per_subcircuit;

        let mut prev_hash_truncated:  Option<[u8; INNER_HASH_SIZE]> = None;

        for subcircuit_idx in 0..self.params.num_subcircuits {
            pm.start_subtrace(ConstraintSystem::<F>::new_ref());

            let hash_result = if subcircuit_idx == 0 {
                // First subcircuit: hash the full 64-byte input
                Self::iterated_sha256_native(&self.inputs[0], num_iters)
            } else {
                // Get from portal (this creates a GET entry in the trace)
                let prev_hash_fp = pm.get(&format! ("hash_{}", subcircuit_idx - 1)).unwrap();
                let _ = prev_hash_fp; // Use the value (even though we compute natively)

                // Subsequent subcircuits: combine prev_hash (padded) with first 32 bytes of input
                let prev = prev_hash_truncated.unwrap();
                let mut padded_prev = [0u8; 32];
                padded_prev[..INNER_HASH_SIZE].copy_from_slice(&prev);

                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&padded_prev);
                combined[32..].copy_from_slice(&self.inputs[subcircuit_idx][..32]);
                Self::iterated_sha256_native(&combined, num_iters)
            };

            // Truncate hash result to INNER_HASH_SIZE (same as digest_to_fpvar does)
            let truncated:  [u8; INNER_HASH_SIZE] =
                hash_result[..INNER_HASH_SIZE].try_into().unwrap();

            // Create FpVar for the truncated hash result and SET it
            let hash_fp = F::from_le_bytes_mod_order(&truncated);
            let hash_fpvar = FpVar::new_witness(ns!(cs, "hash"), || Ok(hash_fp)).unwrap();

            // Store in portal manager (this creates a SET entry in the trace)
            pm.set(format!("hash_{}", subcircuit_idx), &hash_fpvar)
                .unwrap();

            prev_hash_truncated = Some(truncated);
        }

        pm.subtraces
            .into_iter()
            .map(|subtrace| {
                subtrace
                    .into_iter()
                    .map(|e| TranscriptEntry:: Rom(e))
                    .collect()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std:: test_rng;

    #[test]
    fn test_sha256_native_consistency() {
        let mut rng = test_rng();
        let params = Sha256BenchCircuitParams {
            num_subcircuits:  4,
            num_sha_iters_per_subcircuit:  2,
        };

        let mut inputs = vec![[0u8; SHA256_BLOCK_SIZE]; params.num_subcircuits];
        for input in inputs.iter_mut() {
            rng.fill(input);
        }

        let hash1 =
            Sha256BenchCircuit::compute_final_hash(&inputs, params.num_sha_iters_per_subcircuit);
        let hash2 =
            Sha256BenchCircuit::compute_final_hash(&inputs, params.num_sha_iters_per_subcircuit);

        assert_eq!(hash1, hash2, "compute_final_hash should be deterministic");
    }

    #[test]
    fn test_sha256_bench_circuit_satisfied() {
        let mut rng = test_rng();
        let params = Sha256BenchCircuitParams {
            num_subcircuits: 4,
            num_sha_iters_per_subcircuit: 2,
        };

        let mut circ = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, &params);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut pm = SetupRomPortalManager:: <Fr>::new(cs.clone());
        pm.start_subtrace(cs. clone());

        let num_subcircuits =
            <Sha256BenchCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);
        for subcircuit_idx in 0.. num_subcircuits {
            circ.generate_constraints(cs. clone(), subcircuit_idx, &mut pm)
                .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_sha256_bench_get_subtraces() {
        let mut rng = test_rng();
        let params = Sha256BenchCircuitParams {
            num_subcircuits: 4,
            num_sha_iters_per_subcircuit:  2,
        };

        let circ = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, &params);
        let subtraces:  Vec<Vec<TranscriptEntry<Fr>>> = circ.get_portal_subtraces();

        assert_eq!(subtraces.len(), params.num_subcircuits);

        // Verify trace structure: 
        // Subcircuit 0: 1 SET (hash_0)
        // Subcircuit 1+: 1 GET (prev hash) + 1 SET (current hash)
        assert_eq!(subtraces[0].len(), 1, "Subcircuit 0 should have 1 entry (SET)");
        for i in 1..params.num_subcircuits {
            assert_eq!(
                subtraces[i].len(),
                2,
                "Subcircuit {} should have 2 entries (GET + SET)",
                i
            );
        }
    }

    #[test]
    fn test_sha256_bench_various_params() {
        let mut rng = test_rng();

        for num_subcircuits in [2, 4, 8] {
            for num_sha_iters in [1, 2, 4] {
                let params = Sha256BenchCircuitParams {
                    num_subcircuits,
                    num_sha_iters_per_subcircuit:  num_sha_iters,
                };

                let mut circ =
                    <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, &params);
                let cs = ConstraintSystem::<Fr>::new_ref();
                let mut pm = SetupRomPortalManager::<Fr>::new(cs.clone());
                pm. start_subtrace(cs.clone());

                for subcircuit_idx in 0..num_subcircuits {
                    circ.generate_constraints(cs.clone(), subcircuit_idx, &mut pm)
                        .unwrap();
                }

                assert!(
                    cs.is_satisfied().unwrap(),
                    "Circuit should be satisfied for nc={}, ns={}",
                    num_subcircuits,
                    num_sha_iters
                );
            }
        }
    }

    /// Test that get_portal_subtraces produces traces compatible with generate_constraints
    #[test]
    fn test_trace_consistency() {
        let mut rng = test_rng();
        let params = Sha256BenchCircuitParams {
            num_subcircuits: 4,
            num_sha_iters_per_subcircuit: 2,
        };

        let circ = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, &params);

        // Get traces from the fast path
        let fast_traces:  Vec<Vec<TranscriptEntry<Fr>>> = circ.get_portal_subtraces();

        // Get traces from running the actual circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut pm = SetupRomPortalManager::<Fr>::new(cs.clone());

        let mut circ_copy = circ.clone();
        for subcircuit_idx in 0..params.num_subcircuits {
            pm.start_subtrace(ConstraintSystem::<Fr>::new_ref());
            circ_copy
                .generate_constraints(cs. clone(), subcircuit_idx, &mut pm)
                .unwrap();
        }

        let slow_traces: Vec<Vec<TranscriptEntry<Fr>>> = pm
            .subtraces
            . into_iter()
            .map(|st| st.into_iter().map(|e| TranscriptEntry::Rom(e)).collect())
            .collect();

        // Compare trace lengths
        assert_eq!(fast_traces.len(), slow_traces.len());
        for (i, (fast, slow)) in fast_traces.iter().zip(slow_traces.iter()).enumerate() {
            assert_eq!(
                fast.len(),
                slow.len(),
                "Trace length mismatch at subcircuit {}: fast={}, slow={}",
                i,
                fast.len(),
                slow.len()
            );
        }
    }
}