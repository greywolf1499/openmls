//! # Benchmark: Self-Update (Sender Perspective)
//!
//! This benchmark measures the performance of a group member performing a
//! "self-update". This is a fundamental operation in MLS where a member updates
//! their own leaf node in the group's ratchet tree, effectively rotating their
//! client-side keying material.
//!
//! This operation is crucial for maintaining forward secrecy and post-compromise
//! security. The member initiating the update (the "sender" or "updater")
//! creates an `Update` proposal for their own leaf and bundles it into a `Commit`
//! message, which is then broadcast to the group.
//!
//! The performance of this operation is significant as it represents the cost of
//! proactive key rotation, a recommended practice for long-lived groups.
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following sequence of operations:
//! - `MlsGroup::self_update(...)`: Creates an `Update` proposal for the member's
//!   own leaf and stages the corresponding `Commit`.
//! - `MlsGroup::merge_pending_commit(...)`: Finalizes the `Commit` message and
//!   applies the state change to the updater's local `MlsGroup` instance.

#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for a member performing a self-update.
///
/// This function configures a `criterion` benchmark group named
/// "4.1. Group Update (Sender - SelfUpdate)". It iterates through various group
/// sizes, measuring the time it takes for one member to create and apply a
/// `Commit` that updates their own leaf node.
///
/// The setup for each iteration involves creating a full group of the target size,
/// ensuring that the measurement is isolated to the self-update operation itself.
fn benchmark_self_update_sender(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("4.1. Group Update (Sender - SelfUpdate)");
    let ciphersuite = fixture.ciphersuite;

    // SPHINCS+ is significantly slower, so a smaller sample size is used.
    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    for &size in &get_group_sizes() {
        if size == 0 {
            continue; // Cannot have a group of size 0.
        }

        let benchmark_id = BenchmarkId::new(
            "SelfUpdateSender",
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
                        create_member(ciphersuite, &fixture.provider, b"alice_updater");
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
                    (alice_group, alice_signer)
                },
                |(mut alice_group, alice_signer)| {
                    // TIMED: Create and apply the self-update commit.
                    // This is the operation being benchmarked.
                    let (_commit, _welcome, _staged_commit) = alice_group
                        .self_update(
                            &fixture.provider,
                            &alice_signer,
                            LeafNodeParameters::default(),
                        )
                        .expect("Error creating self-update commit.")
                        .into_contents();

                    // Merge the locally staged commit to update the group state.
                    alice_group
                        .merge_pending_commit(&fixture.provider)
                        .expect("Error merging self-update commit.");
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Main entry point for the "Self-Update (Sender)" benchmark suite.
///
/// This function orchestrates the benchmarking process by iterating through the
/// selected ciphersuites, setting up the necessary fixture for each, and then
/// invoking the benchmark function.
fn bench_self_update_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        let fixture = setup_fixture(ciphersuite);
        benchmark_self_update_sender(c, &fixture);
    }
}

criterion_group!(benches, bench_self_update_runner);
criterion_main!(benches);
