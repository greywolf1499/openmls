//! # Benchmark: Member Addition (Existing Member Perspective)
//!
//! This benchmark evaluates the performance of an existing group member processing
//! a `Commit` message that adds a new member to the group. This represents the
//! "receiver-side" cost for a passive participant who is already part of the group.
//!
//! When a member is added, all other existing members receive a `Commit` message
//! over the group's broadcast channel. They must process this message to update
//! their local group state and stay in sync with the rest of the group. This
//! involves validating the committer's signature, applying the changes to the
//! ratchet tree, and deriving the new epoch's shared keys.
//!
//! The performance of this operation is critical for the scalability of the
//! protocol, as its cost is borne by every member of the group for each addition.
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following sequence of operations:
//! - `MlsGroup::process_message(...)`: Parses and validates the incoming `Commit`.
//! - `MlsGroup::merge_staged_commit(...)`: Applies the validated changes to the
//!   local group state, advancing the epoch.

#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for an existing member processing an Add commit.
///
/// This function configures a `criterion` benchmark group named
/// "3.3. Member Addition (Receiver - Existing Member)". It measures the time
/// required for a member of a group of size `n-1` to process a `Commit` from
/// another member that adds a new, `n`-th member.
///
/// The setup for each iteration is complex:
/// 1. A group of `n-1` members is created (e.g., Alice, Charlie, and others).
/// 2. One member (Alice) generates a `Commit` to add a new member (Bob).
/// 3. The benchmark then measures the time it takes for another existing member
///    (Charlie) to process this `Commit` message.
fn benchmark_add_member_receiver_existing(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("3.3. Member Addition (Receiver - Existing Member)");
    let ciphersuite = fixture.ciphersuite;

    // SPHINCS+ is significantly slower, so a smaller sample size is used.
    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    for &size in &get_group_sizes() {
        // We need at least 3 members for this scenario: a committer, a receiver,
        // and the new member being added.
        if size < 3 {
            continue;
        }
        let initial_size = size - 1;

        let benchmark_id = BenchmarkId::new(
            "AddMemberExistingReceiver",
            format!(
                "size={:04}, cs={:?}",
                size,
                ciphersuite.signature_algorithm()
            ),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a group and a commit to be processed.
                    // This part is not measured.

                    // 1. Create the principal actors: Alice (committer), Bob (new member),
                    //    and Charlie (existing member/receiver).
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_member");
                    let (_, _, charlie_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"charlie_member");

                    // 2. Alice creates a group.
                    let group_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &group_config,
                        alice_credential.clone(),
                    )
                    .unwrap();

                    // 3. Alice adds Charlie and other initial members.
                    let mut members_to_add = vec![charlie_key_package.key_package().clone()];
                    members_to_add.extend(
                        fixture
                            .member_pool
                            .iter()
                            .take(initial_size - 2) // -2 for Alice and Charlie
                            .map(|bundle| bundle.key_package().clone()),
                    );

                    let (_, welcome_for_charlie, _) = alice_group
                        .add_members(&fixture.provider, &alice_signer, &members_to_add)
                        .unwrap();
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // 4. Charlie processes the Welcome to join the group.
                    let welcome_msg: MlsMessageIn = welcome_for_charlie.into();
                    let staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        welcome_msg.into_welcome().unwrap(),
                        Some(alice_group.export_ratchet_tree().into()),
                    );
                    let charlie_group = staged_welcome
                        .expect("Error creating staged welcome.")
                        .into_group(&fixture.provider)
                        .unwrap();

                    // 5. Alice creates another commit to add Bob. This is the commit
                    //    that Charlie will process in the timed portion.
                    let (commit_to_process, _, _) = alice_group
                        .add_members(
                            &fixture.provider,
                            &alice_signer,
                            &[bob_key_package.key_package().clone()],
                        )
                        .unwrap();

                    (charlie_group, commit_to_process)
                },
                |(mut existing_member_group, commit)| {
                    // TIMED: An existing member (Charlie) processes the commit.
                    let processed_message = existing_member_group
                        .process_message(&fixture.provider, commit.into_protocol_message().unwrap())
                        .unwrap();

                    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                        processed_message.into_content()
                    {
                        // Merge the commit to update the group state.
                        existing_member_group
                            .merge_staged_commit(&fixture.provider, *staged_commit)
                            .expect("Error merging staged commit");
                    } else {
                        panic!("Expected a StagedCommitMessage");
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Main entry point for the "Add Member (Existing Receiver)" benchmark suite.
///
/// This function orchestrates the benchmarking process by iterating through the
/// selected ciphersuites, setting up the necessary fixture for each, and then
/// invoking the benchmark function.
fn bench_add_member_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        let fixture = setup_fixture(ciphersuite);
        benchmark_add_member_receiver_existing(c, &fixture);
    }
}

criterion_group!(benches, bench_add_member_runner);
criterion_main!(benches);
