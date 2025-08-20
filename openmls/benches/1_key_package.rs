//! # Benchmark: Key Package Creation
//!
//! This benchmark evaluates the performance of creating OpenMLS `KeyPackage`
//! objects. The `KeyPackage` is a fundamental building block in MLS, containing
//! the client's identity, credentials, and cryptographic keys. Its generation is
//! the first step for any member to join a group.
//!
//! The performance of this operation is crucial, particularly when using
//! post-quantum cryptographic algorithms, which may involve more computationally
//! intensive key generation processes and result in larger key sizes compared to
//! their classical counterparts.
//!
//! ## Measured Operation
//!
//! The benchmark measures the time taken for the following operation:
//! - `KeyPackage::builder().build(...)`
//!
//! This includes the generation of the HPKE key pair and the signing of the
//! `KeyPackage`. The setup phase, which includes creating the credential and
//! the signature key pair, is explicitly excluded from the measurement by using
//! `criterion`'s `iter_batched` function, ensuring that only the `build`
//! operation is timed.

#[macro_use]
extern crate criterion;
extern crate openmls;

mod common;

use common::*;
use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

/// Defines and executes the benchmark for `KeyPackage` creation.
///
/// This function configures a `criterion` benchmark group named "1. Key Package Creation".
/// It uses `iter_batched` to ensure that the setup cost (creating credentials and
/// signature key pairs) is separated from the core operation being measured.
///
/// The benchmark is parameterized by the ciphersuite, allowing for a direct
/// comparison of the performance impact of different signature algorithms.
fn benchmark_key_package_creation(c: &mut Criterion, fixture: &KeyPackageBenchFixture) {
    let mut group = c.benchmark_group("1. Key Package Creation");
    let ciphersuite = fixture.ciphersuite;

    // Create a unique ID for the benchmark based on the signature algorithm.
    let benchmark_id = BenchmarkId::new(
        "CreateBundle",
        format!("{:?}", ciphersuite.signature_algorithm()),
    );

    group.bench_function(benchmark_id, move |b| {
        // `iter_batched` runs the setup closure once per batch, then the
        // measurement closure for each iteration within that batch.
        b.iter_batched(
            // Setup: Create the necessary credentials and signature keys.
            // This part is not measured.
            || {
                let credential = BasicCredential::new(b"test_user".to_vec());
                let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
                    .expect("Failed to create signature key pair.");
                let credential_with_key = CredentialWithKey {
                    credential: credential.into(),
                    signature_key: signature_keys.public().into(),
                };
                (credential_with_key, signature_keys)
            },
            // Measurement: Build the KeyPackageBundle. This is the operation
            // being benchmarked.
            |(credential_with_key, signature_keys)| {
                let _key_package_bundle = KeyPackage::builder()
                    .build(
                        ciphersuite,
                        &fixture.provider,
                        &signature_keys,
                        credential_with_key,
                    )
                    .expect("An unexpected error occurred during KeyPackage creation.");
            },
            // Use a small batch size as the setup is relatively inexpensive.
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Main entry point for the key package benchmark suite.
///
/// This function orchestrates the benchmarking process. It retrieves the list of
/// ciphersuites to be tested from the `common` module, then iterates through them.
/// For each ciphersuite, it sets up a lightweight `KeyPackageBenchFixture` and
/// invokes `benchmark_key_package_creation` to run the measurement.
fn bench_key_package(c: &mut Criterion) {
    // Iterate over the ciphersuites selected for testing.
    for &ciphersuite in &get_ciphersuites_to_test() {
        // Set up the lightweight fixture for the current ciphersuite.
        let fixture = setup_key_package_fixture(ciphersuite);
        // Run the benchmark for this ciphersuite.
        benchmark_key_package_creation(c, &fixture);
    }
}

criterion_group!(benches, bench_key_package);
criterion_main!(benches);
