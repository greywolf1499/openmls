//! # Benchmark: Member Addition (New Member Perspective)
//!
//! This benchmark evaluates the performance of a new member joining an existing
//! MLS group. This represents the "receiver-side" cost of a member addition,
//! specifically for the individual being added.
//!
//! The process is initiated when a new member receives a `Welcome` message. This
//! special message, created by an existing group member, contains all the
//! necessary cryptographic material and state information for the new member to
//! initialize their view of the group. The `Welcome` message is encrypted using
//! the new member's `KeyPackage`, ensuring only they can decrypt it.
//!
//! The performance of this operation is a critical aspect of the user experience,
//! as it represents the initial setup time before a new user can participate in
//! the group.
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following sequence of operations:
//! - `StagedWelcome::new_from_welcome(...)`: Parses and decrypts the `Welcome`
//!   message using the new member's keys.
//! - `staged_welcome.into_group(...)`: Constructs the full `MlsGroup` state from
//!   the decrypted `Welcome` data, including building the ratchet tree.

#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for a new member processing a `Welcome` message.
///
/// This function configures a `criterion` benchmark group named
/// "3.2. Member Addition (Receiver - New Member)". It measures the time required
/// for a new member to process a `Welcome` message and instantiate its local
/// `MlsGroup` state, thereby joining a group and bringing it to its final size.
///
/// The setup for each iteration involves creating a group of `n-1` members,
/// having one of them generate a `Welcome` message for the `n`-th member, and
/// then passing this `Welcome` message to the timed portion of the benchmark.
fn benchmark_add_member_receiver_new(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("3.2. Member Addition (Receiver - New Member)");
    let ciphersuite = fixture.ciphersuite;

    // SPHINCS+ is significantly slower, so a smaller sample size is used
    // to keep benchmark execution time reasonable.
    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    for &size in &get_group_sizes() {
        if size < 2 {
            continue; // A new member must join a group of at least one existing member.
        }
        let initial_size = size - 1;

        let benchmark_id = BenchmarkId::new(
            "AddMemberNewReceiver",
            format!(
                "size={:04}, cs={:?}",
                size,
                ciphersuite.signature_algorithm()
            ),
        );

        group.bench_function(benchmark_id, |b| {
            // Use `iter_batched` to separate the setup from the measured code.
            b.iter_batched(
                // Setup: Create a group and a Welcome message for a new member.
                // This part is not measured.
                || {
                    // Create the initial group creator, "Alice".
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");
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
                    .unwrap();

                    // Populate the group to the required initial size.
                    if initial_size > 1 {
                        let key_packages: Vec<KeyPackage> = fixture
                            .member_pool
                            .iter()
                            .take(initial_size - 1)
                            .map(|bundle| bundle.key_package().clone())
                            .collect();
                        alice_group
                            .add_members(&fixture.provider, &alice_signer, &key_packages)
                            .unwrap();
                        alice_group.merge_pending_commit(&fixture.provider).unwrap();
                    }

                    // Create the new member, "Bob", and generate a Welcome message for him.
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_new_member");
                    let (_, welcome, _) = alice_group
                        .add_members(
                            &fixture.provider,
                            &alice_signer,
                            &[bob_key_package.key_package().clone()],
                        )
                        .unwrap();
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // The ratchet tree is provided out-of-band to the new member.
                    let ratchet_tree = Some(alice_group.export_ratchet_tree().into());
                    (welcome, group_config, ratchet_tree)
                },
                // Measurement: Process the Welcome message to join the group.
                // This is the operation being benchmarked.
                |(welcome, group_config, ratchet_tree)| {
                    let welcome_msg: MlsMessageIn = welcome.into();
                    // Stage the welcome message.
                    let staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        welcome_msg.into_welcome().unwrap(),
                        ratchet_tree,
                    )
                    .unwrap();
                    // Build the group state from the staged data.
                    let _bob_group = staged_welcome.into_group(&fixture.provider).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Main entry point for the "Add Member (New Receiver)" benchmark suite.
///
/// This function orchestrates the benchmarking process. It iterates through the
/// ciphersuites selected for testing, sets up the comprehensive `BenchmarkFixture`
/// for each, and then invokes `benchmark_add_member_receiver_new` to perform the
/// actual measurements.
fn bench_add_member_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        let fixture = setup_fixture(ciphersuite);
        benchmark_add_member_receiver_new(c, &fixture);
    }
}

criterion_group!(benches, bench_add_member_runner);
criterion_main!(benches);
