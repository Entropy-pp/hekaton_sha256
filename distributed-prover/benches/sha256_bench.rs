//! Benchmark for SHA256 circuit performance in Hekaton

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ip_proofs::tipa:: TIPA;
use ark_std: :{end_timer, start_timer};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use sha2:: Sha256;

use distributed_prover: :{
    aggregation::AggProvingKey,
    coordinator: :{CoordinatorStage0State, G16ProvingKeyGenerator},
    poseidon_util: :{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig,
        PoseidonTreeConfigVar as TreeConfigVar,
    },
    sha256_bench_circuit: :{Sha256BenchCircuit, Sha256BenchCircuitParams},
    util::G16ProvingKey,
    worker: :{process_stage0_request, process_stage1_request},
    CircuitWithPortals,
};

fn gen_sha256_bench_params(
    num_subcircuits:  usize,
    num_sha_iters:  usize,
) -> Sha256BenchCircuitParams {
    assert!(
        num_subcircuits.is_power_of_two(),
        "num_subcircuits must be a power of 2"
    );
    assert!(num_subcircuits > 1, "num_subcircuits must be > 1");
    assert!(num_sha_iters > 0, "num_sha_iters must be > 0");

    Sha256BenchCircuitParams {
        num_subcircuits,
        num_sha_iters_per_subcircuit:  num_sha_iters,
    }
}

fn generate_sha256_g16_pk(
    circ_params: &Sha256BenchCircuitParams,
) -> G16ProvingKey<E> {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    let circ = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::new(circ_params);

    let generator = G16ProvingKeyGenerator: :<TreeConfig, TreeConfigVar, E, _>::new(
        circ. clone(),
        tree_params. clone(),
    );

    generator.gen_pk(&mut rng, 0)
}

fn sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA256 Circuit");

    // Test various configurations
    for num_subcircuits in [4, 8, 16] {
        for num_sha_iters in [1, 4, 8, 16] {
            let circ_params = gen_sha256_bench_params(num_subcircuits, num_sha_iters);

            let id = BenchmarkId::new(
                "prove",
                format!("nc={},ns={}", num_subcircuits, num_sha_iters),
            );

            group.bench_with_input(id, &circ_params, |b, params| {
                let mut rng = rand::thread_rng();
                let tree_params = gen_merkle_params();

                // Generate proving key
                let pk = generate_sha256_g16_pk(params);

                b.iter(|| {
                    // Create a random circuit instance
                    let circ =
                        <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, params);

                    // Create coordinator state
                    let stage0_state = CoordinatorStage0State::new: :<TreeConfig>(circ);

                    // Process stage 0 for all subcircuits
                    for idx in 0..params.num_subcircuits {
                        let req = stage0_state.gen_request(idx);
                        let _ = process_stage0_request(&req, &pk, tree_params.clone());
                    }
                });
            });
        }
    }

    group.finish();
}

fn sha256_constraint_count(c: &mut Criterion) {
    use ark_relations::r1cs::ConstraintSystem;
    use distributed_prover::portal_manager::SetupRomPortalManager;

    println!("\n=== SHA256 Circuit Constraint Counts ===\n");

    for num_subcircuits in [4, 8, 16, 32] {
        for num_sha_iters in [1, 2, 4, 8, 16, 32] {
            let params = gen_sha256_bench_params(num_subcircuits, num_sha_iters);
            let mut rng = rand::thread_rng();

            let mut circ = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, &params);

            let cs = ConstraintSystem::new_ref();
            let mut pm = SetupRomPortalManager::new(cs.clone());
            pm.start_subtrace(cs.clone());

            // Only measure first subcircuit (representative)
            circ.generate_constraints(cs. clone(), 0, &mut pm).unwrap();

            let constraints_per_subcircuit = cs.num_constraints();
            let total_estimated = constraints_per_subcircuit * num_subcircuits;

            println!(
                "nc={: 3}, ns={:3}:  {: 8} constraints/subcircuit, ~{: 10} total",
                num_subcircuits, num_sha_iters, constraints_per_subcircuit, total_estimated
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = sha256_benchmark
}

criterion_main!(benches);