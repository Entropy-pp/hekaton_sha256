extern crate core;

use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use transcript::{MemType, TranscriptEntry};

pub mod aggregation;
pub mod coordinator;
pub mod eval_tree;
pub mod pairing_ops;
pub mod poseidon_util;
pub mod subcircuit_circuit;
pub mod tree_hash_circuit;
pub mod util;
pub mod worker;

// 在 lib.rs 的模块声明部分添加: 
pub mod sha256_bench_circuit;

// 在 pub use 部分添加: 
pub use sha256_bench_circuit::{Sha256BenchCircuit, Sha256BenchCircuitParams};

use crate::portal_manager::SetupRamPortalManager;
use portal_manager::{PortalManager, ProverPortalManager};

pub mod portal_manager;
pub mod transcript;
pub mod uint32;
pub mod vkd;
pub mod vm;

#[macro_export]
macro_rules! par {
    ($(let $name:ident = $f:expr);+) => {
        $(
            let mut $name = None;
        )+
            rayon::scope(|s| {
                $(
                    let $name = &mut $name;
                    s.spawn(move |_| {
                        *$name = Some($f);
                    });)+
            });
        $(
            let $name = $name.unwrap();
        )+
    };
}

/// A generic trait that any partitionable circuit has to impl
pub trait CircuitWithPortals<F: PrimeField>: Clone {
    // Parameters that define this circuit, e.g., number of subcircuits, number of iterations,
    // public constants, etc.
    type Parameters: Clone + CanonicalSerialize + CanonicalDeserialize + Send;
    type ProverPortalManager: ProverPortalManager<F>;

    const MEM_TYPE: MemType;

    /// Makes a random instance of this circuit with teh given parameters
    fn rand(rng: &mut impl Rng, params: &Self::Parameters) -> Self;

    /// Retreive the set params from the given circuit
    fn get_params(&self) -> Self::Parameters;

    /// Gets all the subtraces of the portal wires used in this circuit instantiation
    fn get_portal_subtraces(&self) -> Vec<Vec<TranscriptEntry<F>>>;

    /// The number of subcircuits in this circuit
    fn num_subcircuits(&self) -> usize;

    /// Returns a minimal set of the unique subcircuits in this circuit. This is for CRS generation.
    fn get_unique_subcircuits(&self) -> Vec<usize>;

    /// Maps a subcircuit index to its canonical representative in the list of unique subcircuits returned by `get_unique_subcircuits`.
    fn representative_subcircuit(&self, subcircuit_idx: usize) -> usize;

    /// Creates an empty copy of this circuit with the given parameters
    fn new(params: &Self::Parameters) -> Self;

    /// Gets the list of witnesses that belong to the given subcircuit
    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8>;

    /// Sets the list of witnesses that belong to the given subcircuit
    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]);

    /// Generates constraints for the subcircuit at the given index. At index i, the ONLY witnesses
    /// the circuit may use are ones which would be set with
    /// `self.set_serialized_witnesses(i, ...)`.
    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError>;
}

pub trait CircuitWithRamPortals<F: PrimeField> {
    // Parameters that define this circuit, e.g., number of subcircuits, number of iterations,
    // public constants, etc.
    type Parameters: Clone + CanonicalSerialize + CanonicalDeserialize;

    /// Retreive the set params from the given circuit
    fn get_params(&self) -> Self::Parameters;

    /// Gets all the subtraces of the portal wires used in this circuit instantiation
    fn get_portal_subtraces(&self) -> SetupRamPortalManager<F>;

    /// The number of subcircuits in this circuit
    fn num_subcircuits(&self) -> usize;

    /// Creates an empty copy of this circuit with the given parameters
    fn new(params: &Self::Parameters) -> Self;

    /// Gets the list of witnesses that belong to the given subcircuit
    fn get_serialized_witnesses(&self, subcircuit_idx: usize) -> Vec<u8>;

    /// Sets the list of witnesses that belong to the given subcircuit
    fn set_serialized_witnesses(&mut self, subcircuit_idx: usize, bytes: &[u8]);

    /// Generates constraints for the subcircuit at the given index. At index i, the ONLY witnesses
    /// the circuit may use are ones which would be set with
    /// `self.set_serialized_witnesses(i, ...)`.
    fn generate_constraints<P: PortalManager<F>>(
        &mut self,
        cs: ConstraintSystemRef<F>,
        subcircuit_idx: usize,
        pm: &mut P,
    ) -> Result<(), SynthesisError>;
}
