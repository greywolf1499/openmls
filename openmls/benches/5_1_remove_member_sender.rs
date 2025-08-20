//! # Benchmark: Member Removal (Sender Perspective)
//!
//! This benchmark measures the performance of a group member removing another
//! member from the group. This represents the "sender-side" cost of a removal
//! operation, where the "sender" is the member initiating the removal.
//!
//! The process involves an existing member creating a `Remove` proposal for
//! another member's leaf node and bundling it into a `Commit` message. This
//! action requires updating the ratchet tree by blanking the removed member's
//! leaf and potentially unmerging parts of the tree. The sender then applies
//! this commit to their own state.
//!
//! The performance of this operation is important for group administration and
//! security, as it is the mechanism for revoking a member's access.
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following sequence of operations:
//! - `MlsGroup::remove_members(...)`: Stages the removal of the member.
//! - `MlsGroup::merge_pending_commit(...)`: Creates the `Commit` message and
//!   updates the sender's local group state.

#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for removing a member from the sender's perspective.
///
/// This function configures a `criterion` benchmark group named "5.1. Member Removal (Sender)".
/// It iterates through various group sizes, measuring the time it takes for one member
/// of a group of size `n` to generate a commit that removes another member.
///
/// The setup for each iteration involves creating a full group of the target size,
/// ensuring that the measurement accurately reflects the cost of the removal
/// operation itself, isolated from prior group setup costs.
fn benchmark_remove_member_sender(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("5.1. Member Removal (Sender)");
    let ciphersuite = fixture.ciphersuite;

    // SPHINCS+ is significantly slower, so a smaller sample size is used.
    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    for &size in &get_group_sizes() {
        // A member can only be removed if there are at least two members.
        if size < 2 {
            continue;
        }

        let benchmark_id = BenchmarkId::new(
            "RemoveMemberSender",
            format!(
                "size={:04}, cs={:?}",
                size,
                ciphersuite.signature_algorithm()
            ),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a group with `size` members.
                    // This part is not measured.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_remover");
                    let group_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &group_config,
                        alice_credential,
                    )
                    .expect("Error creating group for Alice.");

                    // Populate the group to the target size.
                    if size > 1 {
                        let members_to_add: Vec<KeyPackage> = fixture
                            .member_pool
                            .iter()
                            .take(size - 1)
                            .map(|kb| kb.key_package().clone())
                            .collect();
                        alice_group
                            .add_members(&fixture.provider, &alice_signer, &members_to_add)
                            .unwrap();
                        alice_group.merge_pending_commit(&fixture.provider).unwrap();
                    }
                    // We will remove the last member added.
                    let leaf_index_to_remove = LeafNodeIndex::new((size - 1) as u32);
                    (alice_group, alice_signer, leaf_index_to_remove)
                },
                |(mut alice_group, alice_signer, leaf_index_to_remove)| {
                    // TIMED: Create and apply the commit to remove a member.
                    // This is the operation being benchmarked.
                    alice_group
                        .remove_members(&fixture.provider, &alice_signer, &[leaf_index_to_remove])
                        .expect("Error removing member.");
                    alice_group
                        .merge_pending_commit(&fixture.provider)
                        .expect("Error merging removal commit.");
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Main entry point for the "Remove Member (Sender)" benchmark suite.
///
/// This function orchestrates the benchmarking process by iterating through the
/// selected ciphersuites, setting up the necessary fixture for each, and then
/// invoking the benchmark function.
fn bench_remove_member_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        let fixture = setup_fixture(ciphersuite);
        benchmark_remove_member_sender(c, &fixture);
    }
}

criterion_group!(benches, bench_remove_member_runner);
criterion_main!(benches);
