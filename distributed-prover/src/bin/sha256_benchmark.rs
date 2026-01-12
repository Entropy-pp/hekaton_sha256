//! SHA256 Circuit Benchmark for Hekaton System
//!   
//! This binary measures and outputs performance metrics including:
//!  - Setup time (proving key generation)
//! - Commitment time (stage 0)
//! - Proving time (stage 1)
//! - Aggregation time
//!  - Verification time
//!  - Constraint counts

use std::collections::HashMap;
use std::rc::Rc;
use std:: time::Instant;

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_cp_groth16:: verifier::{prepare_verifying_key, verify_proof};
use ark_ip_proofs::tipa:: TIPA;
use ark_serialize:: CanonicalSerialize;
use sha2:: Sha256;

use distributed_prover::{
    aggregation::AggProvingKey,
    coordinator::{CoordinatorStage0State, G16ProvingKeyGenerator, Stage1Request},
    poseidon_util::{
        gen_merkle_params, PoseidonTreeConfig as TreeConfig,
        PoseidonTreeConfigVar as TreeConfigVar,
    },
    sha256_bench_circuit::{Sha256BenchCircuit, Sha256BenchCircuitParams},
    util::G16ProvingKey,
    worker::{process_stage0_request, process_stage1_request, Stage0Response},
    CircuitWithPortals,
};

/// Benchmark results for a single run
#[derive(Debug, Clone)]
struct BenchmarkResult {
    params: Sha256BenchCircuitParams,
    num_constraints_per_subcircuit: usize,
    total_constraints: usize,
    setup_time_ms: f64,
    stage0_time_ms: f64,
    stage1_time_ms: f64,
    aggregation_time_ms: f64,
    total_proving_time_ms: f64,
    verification_time_ms: f64,
    verification_valid: bool,
    proof_size_bytes: usize,
}

impl BenchmarkResult {
    fn print_header() {
        println!("\n{}", "=".repeat(130));
        println!("{:^130}", "SHA256 Circuit Benchmark Results");
        println!("{}", "=". repeat(130));
        println!(
            "{:>6} {:>6} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12} {:>10}",
            "NC", "NS", "Constraints", "Setup(ms)", "Stage0(ms)", "Stage1(ms)", 
            "Agg(ms)", "Total(ms)", "Verify(ms)", "Proof(B)"
        );
        println!("{}", "-".repeat(130));
    }

    fn print(&self) {
        let verify_status = if self.verification_valid { "✓" } else { "✗" };
        println!(
            "{:>6} {: >6} {:>12} {: >12.2} {:>12.2} {:>12.2} {:>12.2} {:>12.2} {:>10.2}{} {:>10}",
            self.params.num_subcircuits,
            self.params.num_sha_iters_per_subcircuit,
            self.total_constraints,
            self.setup_time_ms,
            self.stage0_time_ms,
            self.stage1_time_ms,
            self.aggregation_time_ms,
            self.total_proving_time_ms,
            self.verification_time_ms,
            verify_status,
            self.proof_size_bytes,
        );
    }
}

fn run_benchmark(params: Sha256BenchCircuitParams) -> BenchmarkResult {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    println!(
        "\n>>> Running benchmark for {} subcircuits, {} SHA256 iterations each.. .",
        params.num_subcircuits, params.num_sha_iters_per_subcircuit
    );

    // Create circuit instance
    let circ = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, &params);
    let num_subcircuits = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::num_subcircuits(&circ);
    let all_subcircuit_indices:  Vec<usize> = (0..num_subcircuits).collect();

    // ============ SETUP PHASE ============
    println!("  [1/5] Setup:  Generating proving keys...");
    let setup_start = Instant::now();

    let minimal_proving_keys:  HashMap<usize, Rc<G16ProvingKey<E>>> = {
        let generator = G16ProvingKeyGenerator::<TreeConfig, TreeConfigVar, _, _>::new(
            circ.clone(),
            tree_params.clone(),
        );
        let minimal_subcircuit_indices =
            <Sha256BenchCircuit as CircuitWithPortals<Fr>>::get_unique_subcircuits(&circ);
        minimal_subcircuit_indices
            .iter()
            .map(|&i| (i, Rc::new(generator.gen_pk(&mut rng, i))))
            .collect()
    };

    let proving_keys:  Vec<Rc<G16ProvingKey<E>>> = all_subcircuit_indices
        .iter()
        .map(|&i| {
            let representative_idx =
                <Sha256BenchCircuit as CircuitWithPortals<Fr>>::representative_subcircuit(&circ, i);
            minimal_proving_keys
                .get(&representative_idx)
                .unwrap()
                .clone()
        })
        .collect();

    let setup_time = setup_start. elapsed();
    println!(
        "       Setup completed in {:.2}ms",
        setup_time.as_secs_f64() * 1000.0
    );

    // ============ STAGE 0:  COMMITMENT ============
    println!("  [2/5] Stage 0: Computing commitments...");
    let stage0_start = Instant::now();

    let stage0_state = CoordinatorStage0State::new::<TreeConfig>(circ.clone());

    let stage0_reqs:  Vec<_> = all_subcircuit_indices
        .iter()
        .map(|&idx| stage0_state.gen_request(idx).to_owned())
        .collect();

    let stage0_resps: Vec<Stage0Response<E>> = stage0_reqs
        .iter()
        .zip(proving_keys.iter())
        .map(|(req, pk)| {
            process_stage0_request::<_, TreeConfigVar, _, Sha256BenchCircuit, _>(
                &mut rng,
                tree_params.clone(),
                pk,
                req. clone(),
            )
        })
        .collect();

    let stage0_time = stage0_start.elapsed();
    println!(
        "       Stage 0 completed in {:.2}ms",
        stage0_time.as_secs_f64() * 1000.0
    );

    // ============ STAGE 1: PROVING ============
    println!("  [3/5] Stage 1: Generating proofs...");
    let stage1_start = Instant::now();

    let (tipp_pk, _tipp_vk) = TIPA::<E, Sha256>::setup(num_subcircuits, &mut rng).unwrap();
    let stage1_state =
        stage0_state.process_stage0_responses(&tipp_pk, tree_params.clone(), &stage0_resps);

    let stage1_reqs: Vec<Stage1Request<TreeConfig, _, _>> = all_subcircuit_indices
        .iter()
        .map(|idx| stage1_state.gen_request(*idx).to_owned())
        .collect();

    let stage1_resps: Vec<_> = stage0_reqs
        .into_iter()
        .zip(stage0_resps.into_iter())
        .zip(stage1_reqs.into_iter())
        .zip(proving_keys.iter())
        .map(|(((stage0_req, stage0_resp), stage1_req), pk)| {
            process_stage1_request::<_, TreeConfigVar, _, Sha256BenchCircuit, _>(
                &mut rng,
                tree_params.clone(),
                pk,
                stage0_req,
                &stage0_resp,
                stage1_req,
            )
        })
        .collect();

    let stage1_time = stage1_start.elapsed();
    println!(
        "       Stage 1 completed in {:.2}ms",
        stage1_time.as_secs_f64() * 1000.0
    );

    // ============ AGGREGATION ============
    println!("  [4/5] Aggregating proofs...");
    let agg_start = Instant::now();

    let final_agg_state = stage1_state.into_agg_state();
    let agg_ck = AggProvingKey::new(tipp_pk, |i| &proving_keys[i]);
    let agg_proof = final_agg_state. gen_agg_proof(&agg_ck, &stage1_resps);

    let agg_time = agg_start.elapsed();
    println!(
        "       Aggregation completed in {:.2}ms",
        agg_time.as_secs_f64() * 1000.0
    );

    // Calculate proof size
    let mut proof_bytes = Vec::new();
    agg_proof.serialize_compressed(&mut proof_bytes).unwrap();
    let proof_size = proof_bytes.len();

    // ============ VERIFICATION ============
    println!("  [5/5] Verifying proof...");
    let verify_start = Instant::now();

    // Verify a sample individual proof
    let sample_pk = &proving_keys[0];
    let sample_proof = &stage1_resps[0].proof;
    let public_inputs = final_agg_state.get_public_inputs();
    let pvk = prepare_verifying_key(&sample_pk.vk());
    let is_valid = verify_proof(&pvk, sample_proof, public_inputs).unwrap();

    let verify_time = verify_start.elapsed();

    if is_valid {
        println!(
            "       Verification completed in {:.2}ms (VALID)",
            verify_time. as_secs_f64() * 1000.0
        );
    } else {
        println!(
            "       Verification completed in {:.2}ms (INVALID! )",
            verify_time.as_secs_f64() * 1000.0
        );
    }

    // Calculate constraint count
    let num_constraints_per_subcircuit = estimate_constraints_per_subcircuit(&params);
    let total_constraints = num_constraints_per_subcircuit * num_subcircuits;

    let total_proving_time = stage0_time + stage1_time + agg_time;

    BenchmarkResult {
        params,
        num_constraints_per_subcircuit,
        total_constraints,
        setup_time_ms: setup_time.as_secs_f64() * 1000.0,
        stage0_time_ms: stage0_time. as_secs_f64() * 1000.0,
        stage1_time_ms:  stage1_time.as_secs_f64() * 1000.0,
        aggregation_time_ms: agg_time.as_secs_f64() * 1000.0,
        total_proving_time_ms: total_proving_time.as_secs_f64() * 1000.0,
        verification_time_ms:  verify_time.as_secs_f64() * 1000.0,
        verification_valid: is_valid,
        proof_size_bytes: proof_size,
    }
}

fn estimate_constraints_per_subcircuit(params: &Sha256BenchCircuitParams) -> usize {
    use ark_relations::r1cs:: ConstraintSystem;
    use distributed_prover::portal_manager::SetupRomPortalManager;

    let mut rng = rand::thread_rng();
    let mut circ = <Sha256BenchCircuit as CircuitWithPortals<Fr>>::rand(&mut rng, params);

    let cs = ConstraintSystem::<Fr>::new_ref();
    let mut pm = SetupRomPortalManager::<Fr>::new(cs. clone());
    pm.start_subtrace(cs.clone());

    // Measure subcircuit 0 and 1
    circ.generate_constraints(cs.clone(), 0, &mut pm).unwrap();
    let constraints_0 = cs.num_constraints();

    circ.generate_constraints(cs.clone(), 1, &mut pm).unwrap();
    let constraints_total = cs.num_constraints();

    // Return average
    (constraints_0 + (constraints_total - constraints_0)) / 2
}

fn print_summary(results: &[BenchmarkResult]) {
    println!("\n{}", "=".repeat(130));
    println!("{:^130}", "Performance Summary");
    println!("{}", "=".repeat(130));

    if results.is_empty() {
        println!("No results to summarize.");
        return;
    }

    // Calculate averages and totals
    let total_sha_ops:  usize = results
        .iter()
        .map(|r| r.params.num_subcircuits * r.params.num_sha_iters_per_subcircuit)
        .sum();

    let avg_proving_time:  f64 =
        results.iter().map(|r| r.total_proving_time_ms).sum::<f64>() / results.len() as f64;

    let avg_verify_time: f64 =
        results.iter().map(|r| r.verification_time_ms).sum::<f64>() / results.len() as f64;

    let all_valid = results.iter().all(|r| r.verification_valid);

    println! ("Total benchmark runs:         {}", results.len());
    println!("Total SHA256 operations:     {}", total_sha_ops);
    println!("Average proving time:        {:.2} ms", avg_proving_time);
    println!("Average verification time:   {:.2} ms", avg_verify_time);
    println!(
        "All proofs valid:             {}",
        if all_valid { "YES ✓" } else { "NO ✗" }
    );

    // Find best/worst cases
    if let Some(fastest) = results
        .iter()
        .min_by(|a, b| a.total_proving_time_ms.partial_cmp(&b.total_proving_time_ms).unwrap())
    {
        println!(
            "\nFastest proving:  {} - {:.2} ms",
            fastest.params, fastest.total_proving_time_ms
        );
    }

    if let Some(slowest) = results
        .iter()
        .max_by(|a, b| a.total_proving_time_ms.partial_cmp(&b.total_proving_time_ms).unwrap())
    {
        println!(
            "Slowest proving: {} - {:.2} ms",
            slowest.params, slowest. total_proving_time_ms
        );
    }

    if let Some(fastest_verify) = results
        .iter()
        .min_by(|a, b| a.verification_time_ms.partial_cmp(&b.verification_time_ms).unwrap())
    {
        println!(
            "Fastest verify:   {} - {:.2} ms",
            fastest_verify.params, fastest_verify.verification_time_ms
        );
    }

    println!("{}", "=".repeat(130));
}

fn main() {
    println!("{}", "=".repeat(80));
    println!("{: ^80}", "Hekaton SHA256 Circuit Benchmark");
    println!("{}", "=".repeat(80));
    println!();
    println!("This benchmark measures the performance of SHA256 circuits in the Hekaton system.");
    println!("Metrics include: setup time, commitment, proving, aggregation, and verification.");
    println!();

    // Configure benchmark parameters
    let configs:  Vec<Sha256BenchCircuitParams> = vec![
        // Small configurations for quick testing
        Sha256BenchCircuitParams {
            num_subcircuits: 2,
            num_sha_iters_per_subcircuit:  1,
        },
        Sha256BenchCircuitParams {
            num_subcircuits: 2,
            num_sha_iters_per_subcircuit:  2,
        },
        Sha256BenchCircuitParams {
            num_subcircuits: 4,
            num_sha_iters_per_subcircuit: 1,
        },
        Sha256BenchCircuitParams {
            num_subcircuits: 4,
            num_sha_iters_per_subcircuit: 2,
        },
        // Medium configurations
        Sha256BenchCircuitParams {
            num_subcircuits: 8,
            num_sha_iters_per_subcircuit: 1,
        },
        Sha256BenchCircuitParams {
            num_subcircuits: 8,
            num_sha_iters_per_subcircuit: 2,
        },
        // Larger configurations (uncomment for full benchmark)
        // Sha256BenchCircuitParams { num_subcircuits: 16, num_sha_iters_per_subcircuit: 1 },
        // Sha256BenchCircuitParams { num_subcircuits:  16, num_sha_iters_per_subcircuit:  2 },
    ];

    let mut results = Vec::new();

    for config in configs {
        match std::panic::catch_unwind(|| run_benchmark(config)) {
            Ok(result) => results.push(result),
            Err(_) => {
                eprintln!("Benchmark failed for config: {:?}", config);
            }
        }
    }

    // Print results table
    BenchmarkResult::print_header();
    for result in &results {
        result.print();
    }

    // Print summary
    print_summary(&results);

    // Print detailed breakdown for last result
    if let Some(last) = results.last() {
        println! ("\n{}", "=".repeat(80));
        println!("{:^80}", "Detailed Breakdown (Last Run)");
        println!("{}", "=".repeat(80));
        println!(
            "Configuration:            {} subcircuits × {} SHA256 iters",
            last.params.num_subcircuits, last.params.num_sha_iters_per_subcircuit
        );
        println!(
            "Constraints/subcircuit:  {}",
            last.num_constraints_per_subcircuit
        );
        println!("Total constraints:       {}", last.total_constraints);
        println!();
        println!("Time Breakdown:");
        println!(
            "  Setup (key gen):       {: >10.2} ms ({:>5.1}%)",
            last.setup_time_ms,
            last.setup_time_ms / (last.setup_time_ms + last.total_proving_time_ms) * 100.0
        );
        println!(
            "  Stage 0 (commit):      {:>10.2} ms ({: >5.1}%)",
            last.stage0_time_ms,
            last.stage0_time_ms / last.total_proving_time_ms * 100.0
        );
        println!(
            "  Stage 1 (prove):       {:>10.2} ms ({:>5.1}%)",
            last.stage1_time_ms,
            last.stage1_time_ms / last. total_proving_time_ms * 100.0
        );
        println!(
            "  Aggregation:           {:>10.2} ms ({:>5.1}%)",
            last. aggregation_time_ms,
            last.aggregation_time_ms / last.total_proving_time_ms * 100.0
        );
        println!("  ─────────────────────────────────────");
        println!(
            "  Total proving:          {:>10.2} ms",
            last.total_proving_time_ms
        );
        println!(
            "  Verification:          {:>10.2} ms",
            last.verification_time_ms
        );
        println!();
        println!("Proof size:               {} bytes", last.proof_size_bytes);
        println!(
            "Throughput:              {:.2} constraints/ms",
            last.total_constraints as f64 / last.total_proving_time_ms
        );
        println!(
            "Verification valid:      {}",
            if last.verification_valid {
                "YES ✓"
            } else {
                "NO ✗"
            }
        );
        println!("{}", "=".repeat(80));
    }
}