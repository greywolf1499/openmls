//! # Benchmark: Group Creation
//!
//! This benchmark evaluates the performance of creating a new MLS group with a
//! specified number of initial members. This is a foundational operation in MLS,
//! representing the initial setup cost of a secure group communication session.
//!
//! The process involves one member (the creator) initiating the group and then
//! adding a batch of other members in the first transaction. This operation is
//! computationally intensive as it requires the construction of the initial ratchet
//! tree, the processing of multiple `KeyPackage`s, and the generation of a `Commit`
//! message that establishes the initial group state.
//!
//! The performance is evaluated across different group sizes and for various
//! ciphersuites, including classical and post-quantum schemes, to analyze the
//! impact of the underlying cryptography on this critical path.
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following sequence of operations:
//! 1. `MlsGroup::new(...)`: Initializes the group for the creator.
//! 2. `MlsGroup::add_members(...)`: Stages the addition of new members.
//! 3. `MlsGroup::merge_pending_commit(...)`: Processes the staged additions and
//!    establishes the initial shared group state.
//!
//! The setup, which includes generating the creator's identity and collecting the
//! key packages for the other members, is performed outside the timed loop.

#[macro_use]
extern crate criterion;
extern crate openmls;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for group creation.
///
/// This function configures a `criterion` benchmark group named "2. Group Creation".
/// It iterates through a predefined set of group sizes and ciphersuites. For each
/// combination, it measures the time to create a group and add the initial members.
///
/// A smaller sample size is used for SPHINCS+ ciphersuites due to their significantly
/// higher computational cost, ensuring that the benchmark can complete in a
/// reasonable timeframe.
fn benchmark_group_creation(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("2. Group Creation");
    let ciphersuite = fixture.ciphersuite;

    // SPHINCS+ is significantly slower, so a smaller sample size is used
    // to keep benchmark execution time reasonable.
    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    // Iterate over the configured group sizes to test.
    for &size in &get_group_sizes() {
        // Create a unique ID for this specific benchmark case.
        let benchmark_id = BenchmarkId::new(
            "CreateGroup",
            format!(
                "size={:04}, cs={:?}",
                size,
                ciphersuite.signature_algorithm()
            ),
        );

        group.bench_function(benchmark_id, |b| {
            // Use `iter_batched` to separate setup from the measured code.
            b.iter_batched(
                // Setup: Prepare all necessary components for group creation.
                // This part is not measured.
                || {
                    let (alice_credential_with_key, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");
                    let mls_group_create_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();
                    // Collect key packages for the members to be added.
                    let member_key_packages: Vec<KeyPackage> = fixture
                        .member_pool
                        .iter()
                        .take(size - 1) // Group creator is the first member.
                        .map(|kb| kb.key_package().clone())
                        .collect();
                    (
                        alice_signer,
                        mls_group_create_config,
                        alice_credential_with_key,
                        member_key_packages,
                    )
                },
                // Measurement: Create the group, add members, and merge the commit.
                // This is the operation being benchmarked.
                |(
                    alice_signer,
                    mls_group_create_config,
                    alice_credential_with_key,
                    member_key_packages,
                )| {
                    // Alice creates the group.
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &mls_group_create_config,
                        alice_credential_with_key,
                    )
                    .expect("Error creating group.");
                    // If there are other members, add them in the initial commit.
                    if !member_key_packages.is_empty() {
                        alice_group
                            .add_members(&fixture.provider, &alice_signer, &member_key_packages)
                            .expect("Error adding members.");
                        // Process the pending commit to finalize the group state.
                        alice_group
                            .merge_pending_commit(&fixture.provider)
                            .expect("Error merging commit after adding members.");
                    }
                },
                // The setup is re-run for each measurement to ensure isolation.
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Main entry point for the group creation benchmark suite.
///
/// This function orchestrates the benchmarking process. It iterates through the
/// ciphersuites selected for testing, sets up the comprehensive `BenchmarkFixture`
/// for each, and then invokes `benchmark_group_creation` to perform the
/// actual measurements.
fn bench_group_creation_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        // The fixture provides a pre-generated pool of members, which is
        // essential for this benchmark.
        let fixture = setup_fixture(ciphersuite);
        benchmark_group_creation(c, &fixture);
    }
}

criterion_group!(benches, bench_group_creation_runner);
criterion_main!(benches);
