//! SHA256 Circuit Benchmark for Hekaton System
//!
//! This binary measures and outputs performance metrics including:
//! - Setup time (proving key generation)
//! - Per-worker commitment time (stage 0)
//! - Per-worker proving time (stage 1)
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

/// Per-worker timing information
#[derive(Debug, Clone)]
struct WorkerTiming {
    worker_id: usize,
    stage0_time_ms: f64,
    stage1_time_ms: f64,
}

/// Benchmark results for a single run
#[derive(Debug, Clone)]
struct BenchmarkResult {
    params: Sha256BenchCircuitParams,
    num_constraints_per_subcircuit: usize,
    total_constraints: usize,
    setup_time_ms: f64,
    // Per-worker timings
    worker_timings: Vec<WorkerTiming>,
    // Aggregated stats
    stage0_total_ms: f64,
    stage0_avg_ms: f64,
    stage0_min_ms: f64,
    stage0_max_ms: f64,
    stage1_total_ms: f64,
    stage1_avg_ms: f64,
    stage1_min_ms: f64,
    stage1_max_ms: f64,
    // Other timings
    aggregation_time_ms: f64,
    verification_time_ms: f64,
    verification_valid:  bool,
    proof_size_bytes: usize,
}

impl BenchmarkResult {
    fn print_summary_header() {
        println!("\n{}", "=".repeat(140));
        println!("{: ^140}", "SHA256 Circuit Benchmark Summary");
        println!("{}", "=".repeat(140));
        println!(
            "{:>4} {:>4} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "NC", "NS", "Constr.", "Setup", "S0-Avg", "S0-Min", "S0-Max", 
            "S1-Avg", "S1-Min", "S1-Max", "Agg", "Verify"
        );
        println!(
            "{:>4} {:>4} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            "", "", "", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)", "(ms)"
        );
        println!("{}", "-".repeat(140));
    }

    fn print_summary(&self) {
        let verify_status = if self.verification_valid { "✓" } else { "✗" };
        println!(
            "{:>4} {:>4} {:>10} {:>10.1} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>10.2} {:>8.2}{}",
            self.params.num_subcircuits,
            self.params.num_sha_iters_per_subcircuit,
            self.total_constraints,
            self.setup_time_ms,
            self.stage0_avg_ms,
            self.stage0_min_ms,
            self.stage0_max_ms,
            self.stage1_avg_ms,
            self.stage1_min_ms,
            self. stage1_max_ms,
            self.aggregation_time_ms,
            self.verification_time_ms,
            verify_status,
        );
    }

    fn print_worker_details(&self) {
        println!("\n{}", "=".repeat(80));
        println!("{:^80}", "Per-Worker Timing Details");
        println!("{}", "=".repeat(80));
        println!(
            "{:>10} {:>15} {:>15} {:>15}",
            "Worker", "Stage0 (ms)", "Stage1 (ms)", "Total (ms)"
        );
        println! ("{}", "-".repeat(80));

        for timing in &self.worker_timings {
            let total = timing.stage0_time_ms + timing.stage1_time_ms;
            println!(
                "{:>10} {: >15.2} {:>15.2} {:>15.2}",
                timing.worker_id, timing.stage0_time_ms, timing.stage1_time_ms, total
            );
        }

        println!("{}", "-".repeat(80));
        println!(
            "{:>10} {: >15.2} {:>15.2} {:>15.2}",
            "Total",
            self.stage0_total_ms,
            self.stage1_total_ms,
            self.stage0_total_ms + self.stage1_total_ms
        );
        println!(
            "{:>10} {: >15.2} {:>15.2} {:>15.2}",
            "Average",
            self.stage0_avg_ms,
            self.stage1_avg_ms,
            self.stage0_avg_ms + self.stage1_avg_ms
        );
        println!(
            "{:>10} {:>15.2} {:>15.2}",
            "Min", self.stage0_min_ms, self.stage1_min_ms
        );
        println!(
            "{:>10} {: >15.2} {:>15.2}",
            "Max", self.stage0_max_ms, self.stage1_max_ms
        );
        println!("{}", "=".repeat(80));
    }
}

fn run_benchmark(params: Sha256BenchCircuitParams) -> BenchmarkResult {
    let mut rng = rand::thread_rng();
    let tree_params = gen_merkle_params();

    println!(
        "\n>>> Running benchmark:  {} subcircuits (workers), {} SHA256 iterations each",
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
        setup_time. as_secs_f64() * 1000.0
    );

    // ============ STAGE 0:  COMMITMENT (Per-Worker Timing) ============
    println!("  [2/5] Stage 0: Computing commitments (per-worker timing)...");

    let stage0_state = CoordinatorStage0State::new::<TreeConfig>(circ.clone());

    let stage0_reqs:  Vec<_> = all_subcircuit_indices
        .iter()
        .map(|&idx| stage0_state.gen_request(idx).to_owned())
        .collect();

    // Measure each worker's stage0 time individually
    let mut stage0_times: Vec<f64> = Vec::with_capacity(num_subcircuits);
    let mut stage0_resps: Vec<Stage0Response<E>> = Vec::with_capacity(num_subcircuits);

    for (idx, (req, pk)) in stage0_reqs.iter().zip(proving_keys.iter()).enumerate() {
        let worker_start = Instant::now();
        
        let resp = process_stage0_request::<_, TreeConfigVar, _, Sha256BenchCircuit, _>(
            &mut rng,
            tree_params.clone(),
            pk,
            req. clone(),
        );
        
        let worker_time = worker_start.elapsed().as_secs_f64() * 1000.0;
        stage0_times.push(worker_time);
        stage0_resps.push(resp);
        
        println! ("       Worker {}: Stage0 completed in {:.2}ms", idx, worker_time);
    }

    let stage0_total:  f64 = stage0_times.iter().sum();
    let stage0_avg = stage0_total / num_subcircuits as f64;
    let stage0_min = stage0_times.iter().cloned().fold(f64:: INFINITY, f64::min);
    let stage0_max = stage0_times.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    println!(
        "       Stage 0 total: {:.2}ms, avg: {:.2}ms, min: {:.2}ms, max: {:.2}ms",
        stage0_total, stage0_avg, stage0_min, stage0_max
    );

    // ============ STAGE 1: PROVING (Per-Worker Timing) ============
    println!("  [3/5] Stage 1: Generating proofs (per-worker timing)...");

    let (tipp_pk, _tipp_vk) = TIPA::<E, Sha256>::setup(num_subcircuits, &mut rng).unwrap();
    let stage1_state =
        stage0_state.process_stage0_responses(&tipp_pk, tree_params.clone(), &stage0_resps);

    let stage1_reqs: Vec<Stage1Request<TreeConfig, _, _>> = all_subcircuit_indices
        .iter()
        .map(|idx| stage1_state.gen_request(*idx).to_owned())
        .collect();

    // Measure each worker's stage1 time individually
    let mut stage1_times: Vec<f64> = Vec::with_capacity(num_subcircuits);
    let mut stage1_resps: Vec<_> = Vec::with_capacity(num_subcircuits);

    for (idx, (((stage0_req, stage0_resp), stage1_req), pk)) in stage0_reqs
        .clone()
        .into_iter()
        .zip(stage0_resps.iter())
        .zip(stage1_reqs.into_iter())
        .zip(proving_keys.iter())
        .enumerate()
    {
        let worker_start = Instant::now();
        
        let resp = process_stage1_request::<_, TreeConfigVar, _, Sha256BenchCircuit, _>(
            &mut rng,
            tree_params.clone(),
            pk,
            stage0_req,
            stage0_resp,
            stage1_req,
        );
        
        let worker_time = worker_start.elapsed().as_secs_f64() * 1000.0;
        stage1_times.push(worker_time);
        stage1_resps.push(resp);
        
        println!("       Worker {}: Stage1 completed in {:.2}ms", idx, worker_time);
    }

    let stage1_total: f64 = stage1_times.iter().sum();
    let stage1_avg = stage1_total / num_subcircuits as f64;
    let stage1_min = stage1_times.iter().cloned().fold(f64::INFINITY, f64::min);
    let stage1_max = stage1_times.iter().cloned().fold(f64::NEG_INFINITY, f64:: max);

    println!(
        "       Stage 1 total:  {:.2}ms, avg: {:.2}ms, min: {:.2}ms, max: {:.2}ms",
        stage1_total, stage1_avg, stage1_min, stage1_max
    );

    // Build worker timings
    let worker_timings: Vec<WorkerTiming> = (0..num_subcircuits)
        .map(|i| WorkerTiming {
            worker_id: i,
            stage0_time_ms: stage0_times[i],
            stage1_time_ms: stage1_times[i],
        })
        .collect();

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

    let sample_pk = &proving_keys[0];
    let sample_proof = &stage1_resps[0]. proof;
    let public_inputs = final_agg_state.get_public_inputs();
    let pvk = prepare_verifying_key(&sample_pk. vk());
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

    BenchmarkResult {
        params,
        num_constraints_per_subcircuit,
        total_constraints,
        setup_time_ms: setup_time.as_secs_f64() * 1000.0,
        worker_timings,
        stage0_total_ms: stage0_total,
        stage0_avg_ms: stage0_avg,
        stage0_min_ms: stage0_min,
        stage0_max_ms: stage0_max,
        stage1_total_ms: stage1_total,
        stage1_avg_ms: stage1_avg,
        stage1_min_ms: stage1_min,
        stage1_max_ms: stage1_max,
        aggregation_time_ms: agg_time.as_secs_f64() * 1000.0,
        verification_time_ms: verify_time.as_secs_f64() * 1000.0,
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

    circ.generate_constraints(cs.clone(), 0, &mut pm).unwrap();
    let constraints_0 = cs.num_constraints();

    circ.generate_constraints(cs. clone(), 1, &mut pm).unwrap();
    let constraints_total = cs.num_constraints();

    (constraints_0 + (constraints_total - constraints_0)) / 2
}

fn print_final_summary(results: &[BenchmarkResult]) {
    println!("\n{}", "=".repeat(140));
    println!("{:^140}", "Final Performance Summary");
    println!("{}", "=".repeat(140));

    if results.is_empty() {
        println!("No results to summarize.");
        return;
    }

    let all_valid = results.iter().all(|r| r.verification_valid);

    println!(
        "Total benchmark runs:           {}",
        results.len()
    );
    println!(
        "All proofs valid:              {}",
        if all_valid { "YES ✓" } else { "NO ✗" }
    );

    // Find best single worker time
    let best_worker = results
        .iter()
        .flat_map(|r| r. worker_timings.iter())
        .min_by(|a, b| {
            (a.stage0_time_ms + a.stage1_time_ms)
                .partial_cmp(&(b.stage0_time_ms + b.stage1_time_ms))
                .unwrap()
        });

    if let Some(worker) = best_worker {
        println!(
            "\nFastest single worker:          Worker {} ({:.2}ms total)",
            worker.worker_id,
            worker.stage0_time_ms + worker.stage1_time_ms
        );
    }

    // Parallel vs Sequential comparison
    println! ("\n{}", "-".repeat(80));
    println!("{:^80}", "Parallel Speedup Analysis");
    println!("{}", "-".repeat(80));

    for result in results {
        let sequential_time = result.stage0_total_ms + result.stage1_total_ms;
        let parallel_time = result.stage0_max_ms + result.stage1_max_ms + result.aggregation_time_ms;
        let speedup = sequential_time / parallel_time;

        println!(
            "Config [nc={}, ns={}]:",
            result.params.num_subcircuits, result.params.num_sha_iters_per_subcircuit
        );
        println!("  Sequential time (sum):     {:.2}ms", sequential_time);
        println!(
            "  Parallel time (max+agg):   {:.2}ms",
            parallel_time
        );
        println! ("  Theoretical speedup:       {:.2}x", speedup);
        println!();
    }

    println! ("{}", "=".repeat(140));
}

fn main() {
    println!("{}", "=".repeat(80));
    println!("{: ^80}", "Hekaton SHA256 Circuit Benchmark");
    println!("{: ^80}", "Per-Worker Timing Analysis");
    println!("{}", "=".repeat(80));
    println!();
    println!("This benchmark measures per-worker performance in the Hekaton system.");
    println!("Each worker (subcircuit) is timed individually for Stage0 and Stage1.");
    println!();

    // Configure benchmark parameters
    let configs:  Vec<Sha256BenchCircuitParams> = vec![
        Sha256BenchCircuitParams {
            num_subcircuits: 2,
            num_sha_iters_per_subcircuit: 1,
        },
        Sha256BenchCircuitParams {
            num_subcircuits: 4,
            num_sha_iters_per_subcircuit: 1,
        },
        Sha256BenchCircuitParams {
            num_subcircuits: 4,
            num_sha_iters_per_subcircuit:  2,
        },
        Sha256BenchCircuitParams {
            num_subcircuits: 8,
            num_sha_iters_per_subcircuit: 2,
        },
        // Uncomment for larger tests
        // Sha256BenchCircuitParams {
        //     num_subcircuits: 16,
        //     num_sha_iters_per_subcircuit: 2,
        // },
    ];

    let mut results = Vec::new();

    for config in configs {
        match std::panic::catch_unwind(|| run_benchmark(config)) {
            Ok(result) => {
                // Print per-worker details for this run
                result.print_worker_details();
                results.push(result);
            }
            Err(_) => {
                eprintln!("Benchmark failed for config: {:?}", config);
            }
        }
    }

    // Print summary table
    BenchmarkResult::print_summary_header();
    for result in &results {
        result.print_summary();
    }

    // Print final analysis
    print_final_summary(&results);

    // Print detailed breakdown for last result
    if let Some(last) = results.last() {
        println!("\n{}", "=". repeat(80));
        println!("{:^80}", "Detailed Breakdown (Last Run)");
        println!("{}", "=".repeat(80));
        println!(
            "Configuration:             {} workers × {} SHA256 iters",
            last.params.num_subcircuits, last.params. num_sha_iters_per_subcircuit
        );
        println!(
            "Constraints/worker:       {}",
            last.num_constraints_per_subcircuit
        );
        println!("Total constraints:        {}", last.total_constraints);
        println!();
        println!("Stage 0 (Commitment):");
        println!("  Total time:              {:.2}ms", last.stage0_total_ms);
        println!("  Average per worker:     {:.2}ms", last.stage0_avg_ms);
        println!("  Min worker time:        {:.2}ms", last.stage0_min_ms);
        println!("  Max worker time:        {:.2}ms", last.stage0_max_ms);
        println!();
        println!("Stage 1 (Proving):");
        println!("  Total time:              {:.2}ms", last.stage1_total_ms);
        println!("  Average per worker:     {:.2}ms", last.stage1_avg_ms);
        println!("  Min worker time:        {:.2}ms", last.stage1_min_ms);
        println!("  Max worker time:        {:.2}ms", last.stage1_max_ms);
        println!();
        println!("Other:");
        println!("  Setup time:             {:.2}ms", last.setup_time_ms);
        println!("  Aggregation time:       {:.2}ms", last.aggregation_time_ms);
        println!("  Verification time:      {:.2}ms", last.verification_time_ms);
        println!("  Proof size:             {} bytes", last.proof_size_bytes);
        println!();
        println!(
            "Throughput:                {:.2} constraints/ms (per worker avg)",
            last.num_constraints_per_subcircuit as f64 / (last.stage0_avg_ms + last.stage1_avg_ms)
        );
        println! ("{}", "=".repeat(80));
    }
}