//! # Benchmark: Application Messaging (Sender Perspective)
//!
//! This benchmark evaluates the performance of creating and encrypting an
//! application message for sending to the group. This is arguably the most
//! frequent operation in any secure messaging system after the initial setup,
//! making its performance critical to the user experience.
//!
//! The process involves a group member taking a plaintext message, deriving the
//! appropriate encryption key for the current epoch from the group's shared
//! secret tree, and using an AEAD (Authenticated Encryption with Associated Data)
//! scheme to encrypt the message. The payload is also signed for authentication.
//!
//! The performance of this operation is primarily dependent on the efficiency of
//! the AEAD algorithm specified by the group's ciphersuite.
//!
//! ## Measured Operations
//!
//! The benchmark measures the time taken for the following operation:
//! - `MlsGroup::create_message(...)`: Derives the sender data key and nonce,
//!   and performs AEAD encryption on the application payload.

#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;

/// Defines and executes the benchmark for sending an application message.
///
/// This function configures a `criterion` benchmark group named "6.1. Application Message (Send)".
/// It iterates through various group sizes to confirm that message creation time is
/// independent of the number of members. For each size, it measures the time taken
/// for a member to encrypt a sample application message.
///
/// The setup for each iteration involves creating a stable, fully initialized group
/// of the target size.
fn benchmark_send_application_message(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("6.1. Application Message (Send)");
    let ciphersuite = fixture.ciphersuite;

    if is_sphincs_ciphersuite(ciphersuite) {
        group.sample_size(50);
    }

    for &size in &get_group_sizes() {
        // Messaging requires a group with at least one member (the sender).
        // A group of 2 is the minimum for a meaningful interaction.
        if size < 2 {
            continue;
        }

        let benchmark_id = BenchmarkId::new(
            "SendMessage",
            format!(
                "size={:04}, cs={:?}",
                size,
                ciphersuite.signature_algorithm()
            ),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a stable group of `size` members.
                    // This part is not measured.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_sender");
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
                    let message_payload = b"This is a test message.";
                    (alice_group, alice_signer, message_payload)
                },
                |(mut alice_group, alice_signer, message_payload)| {
                    // TIMED: The cost of deriving the key and encrypting the message.
                    // This is the operation being benchmarked.
                    let _ = alice_group
                        .create_message(&fixture.provider, &alice_signer, message_payload)
                        .expect("Error creating application message.");
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Main entry point for the "Application Messaging (Send)" benchmark suite.
///
/// This function orchestrates the benchmarking process by iterating through the
/// selected ciphersuites, setting up the necessary fixture for each, and then
/// invoking the benchmark function.
fn bench_messaging_runner(c: &mut Criterion) {
    for &ciphersuite in &get_ciphersuites_to_test() {
        let fixture = setup_fixture(ciphersuite);
        benchmark_send_application_message(c, &fixture);
    }
}

criterion_group!(benches, bench_messaging_runner);
criterion_main!(benches);
