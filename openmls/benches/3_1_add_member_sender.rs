//! # Benchmark: Member Addition (Sender Perspective)
//!
//! This benchmark measures the performance of an existing group member adding a
//! new member to the group. This represents the "sender-side" cost of a member
//! addition operation.
//!
//! The process involves the existing member (the "sender" or "committer")
//! creating a `Commit` message that includes an `Add` proposal for the new member.
//! This operation requires the sender to:
//! 1. Process the new member's `KeyPackage`.
//! 2. Create a `Welcome` message to securely deliver the new group state to the
//!    joining member.
//! 3. Update their own view of the group state by applying the `Commit`.
//!
//! The computational cost is influenced by the group size (due to tree operations)
//! and the chosen ciphersuite (signature generation for the commit, and HPKE
//! operations for the `Welcome` message).
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following sequence of operations:
//! - `MlsGroup::add_members(...)`: Stages the addition of the new member.
//! - `MlsGroup::merge_pending_commit(...)`: Creates the `Commit` and `Welcome`
//!   messages and updates the sender's local group state.

#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for adding a member from the sender's perspective.
///
/// This function configures a `criterion` benchmark group named "3.1. Member Addition (Sender)".
/// It iterates through various group sizes, measuring the time it takes for a member
/// of a group of size `n-1` to generate a commit that adds the `n`-th member.
///
/// The setup for each iteration involves creating a fully functional group of the
/// required initial size, ensuring that the measurement accurately reflects the
/// cost of the add operation itself, isolated from prior group setup costs.
fn benchmark_add_member_sender(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("3.1. Member Addition (Sender)");
    let ciphersuite = fixture.ciphersuite;

    // SPHINCS+ is significantly slower, so a smaller sample size is used
    // to keep benchmark execution time reasonable.
    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    for &size in &get_group_sizes() {
        // The benchmark measures adding a member to a group of `initial_size`
        // to reach the target `size`.
        let initial_size = size - 1;
        if initial_size == 0 {
            continue; // A group must have at least one member to add another.
        }

        let benchmark_id = BenchmarkId::new(
            "AddMemberSender",
            format!(
                "size={:04}, cs={:?}",
                size,
                ciphersuite.signature_algorithm()
            ),
        );

        group.bench_function(benchmark_id, |b| {
            // Use `iter_batched` to create a fresh group for each measurement.
            b.iter_batched(
                // Setup: Create a stable group of `initial_size`.
                // This part is not measured.
                || {
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");
                    let mls_group_create_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &mls_group_create_config,
                        alice_credential,
                    )
                    .unwrap();

                    // Populate the group to the required initial size.
                    if initial_size > 1 {
                        let members_to_add: Vec<KeyPackage> = fixture
                            .member_pool
                            .iter()
                            .take(initial_size - 1)
                            .map(|bundle| bundle.key_package().clone())
                            .collect();
                        alice_group
                            .add_members(&fixture.provider, &alice_signer, &members_to_add)
                            .unwrap();
                        alice_group.merge_pending_commit(&fixture.provider).unwrap();
                    }
                    // Prepare the key package for the new member to be added.
                    let new_member_kp = fixture.new_member_kp_bundle.key_package().clone();
                    (alice_group, alice_signer, new_member_kp)
                },
                // Measurement: Add the new member and process the commit.
                // This is the operation being benchmarked.
                |(mut group_creator, creator_signer, new_member_kp)| {
                    // This creates the `Commit` and `Welcome` messages.
                    let _ = group_creator
                        .add_members(&fixture.provider, &creator_signer, &[new_member_kp])
                        .expect("Error adding member");
                    // This updates the sender's local state.
                    group_creator
                        .merge_pending_commit(&fixture.provider)
                        .expect("Error merging commit after adding member.");
                },
                // Use a small batch size as the setup is complex.
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Main entry point for the "Add Member (Sender)" benchmark suite.
///
/// This function orchestrates the benchmarking process. It iterates through the
/// ciphersuites selected for testing, sets up the comprehensive `BenchmarkFixture`
/// for each, and then invokes `benchmark_add_member_sender` to perform the
/// actual measurements.
fn bench_add_member_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        let fixture = setup_fixture(ciphersuite);
        benchmark_add_member_sender(c, &fixture);
    }
}

criterion_group!(benches, bench_add_member_runner);
criterion_main!(benches);
