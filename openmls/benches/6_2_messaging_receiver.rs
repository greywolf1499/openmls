//! # Benchmark: Application Messaging (Receiver Perspective)
//!
//! This benchmark evaluates the performance of processing and decrypting an
//! incoming application message. This represents the "receiver-side" cost of
//! messaging and is a frequent operation in any active group chat.
//!
//! The process involves a group member receiving an `MlsMessageOut`, parsing it
//! to identify the sender, looking up the appropriate decryption key from the
//! secret tree for the current epoch, and performing AEAD decryption to recover
//! the original plaintext and verify its authenticity.
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following operation:
//! - `MlsGroup::process_message(...)`: Parses the incoming message, derives the
//!   sender data key and nonce, and performs AEAD decryption and verification.

#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for receiving an application message.
///
/// This function configures a `criterion` benchmark group named "6.2. Application Message (Receive)".
/// It measures the time required for one member of a group to process and decrypt an
/// application message sent by another member.
///
/// The setup for each iteration is as follows:
/// 1. A group of `n` members is created, including Alice (the sender) and Bob (the receiver).
/// 2. The states of Alice's and Bob's group instances are synchronized.
/// 3. Alice creates an encrypted application message and signature.
/// 4. The benchmark then measures the time it takes for Bob to process this message.
fn benchmark_receive_application_message(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("6.2. Application Message (Receive)");
    let ciphersuite = fixture.ciphersuite;

    // Reduce sample size for SPHINCS+ to keep the setup phase from dominating.
    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    for &size in &get_group_sizes() {
        // This scenario requires at least two members: a sender and a receiver.
        if size < 2 {
            continue;
        }

        let benchmark_id = BenchmarkId::new(
            "ReceiveMessage",
            format!(
                "size={:04}, cs={:?}",
                size,
                ciphersuite.signature_algorithm()
            ),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a stable group, have Alice send a message,
                    // and prepare Bob to receive it. This part is not measured.

                    // 1. Create the main actors: Alice (sender) and Bob (receiver).
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_sender");
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_receiver");

                    // 2. Alice creates a group.
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

                    // 3. Alice adds Bob and all other members to the group.
                    let mut members_to_add: Vec<KeyPackage> =
                        vec![bob_key_package.key_package().clone()];
                    members_to_add.extend(
                        fixture
                            .member_pool
                            .iter()
                            .take(size - 2) // -2 for Alice and Bob
                            .map(|kb| kb.key_package().clone()),
                    );

                    let (_, welcome, _) = alice_group
                        .add_members(&fixture.provider, &alice_signer, &members_to_add)
                        .unwrap();
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // 4. Bob processes the Welcome to create his synchronized group instance.
                    let welcome_msg: MlsMessageIn = welcome.into();
                    let staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        welcome_msg.into_welcome().unwrap(),
                        Some(alice_group.export_ratchet_tree().into()),
                    )
                    .unwrap();
                    let bob_group = staged_welcome.into_group(&fixture.provider).unwrap();

                    // 5. Alice creates the message that Bob will process.
                    let application_message = alice_group
                        .create_message(&fixture.provider, &alice_signer, b"Hello, Bob!")
                        .unwrap();
                    (bob_group, application_message)
                },
                |(mut bob_group, application_message)| {
                    // TIMED: The cost of decrypting and verifying the message.
                    // This is the operation being benchmarked.
                    let _processed_message = bob_group
                        .process_message(
                            &fixture.provider,
                            application_message.into_protocol_message().unwrap(),
                        )
                        .expect("Error processing application message.");
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Main entry point for the "Application Messaging (Receive)" benchmark suite.
///
/// This function orchestrates the benchmarking process by iterating through the
/// selected ciphersuites, setting up the necessary fixture for each, and then
/// invoking the benchmark function.
fn bench_messaging_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        let fixture = setup_fixture(ciphersuite);
        benchmark_receive_application_message(c, &fixture);
    }
}

criterion_group!(benches, bench_messaging_runner);
criterion_main!(benches);
