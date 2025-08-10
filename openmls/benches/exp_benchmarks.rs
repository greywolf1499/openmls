#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

// ─── Constants And Configuration ─────────────────────────────────────────────

// ─── Helper Functions ────────────────────────────────────────────────────────

// ─── 1. Keypackage Creation ──────────────────────────────────────────────────
// # Benchmark: Key Package Creation
// * Objective: Measures the time for a single user to generate their cryptographic identity
// * and create a KeyPackageBundle. This captures the foundational per-user cost before joining any group.
fn benchmark_key_package_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("1. Key Package Creation");
    let provider = &OpenMlsRustCrypto::default();

    // Iterate over all supported ciphersuites to test each one.
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        // Use the ciphersuite name as a parameter for the benchmark ID.
        let benchmark_id = BenchmarkId::new("CreateBundle", format!("{:?}", ciphersuite));

        group.bench_function(benchmark_id, move |b| {
            // The setup closure prepares the necessary inputs, and the timed
            // routine consumes them. SmallInput is efficient as the setup
            // is lightweight and not stateful in a way that affects subsequent runs.
            b.iter_batched(
                || {
                    // SETUP: This part is not timed.
                    // 1. Create a basic credential for the user.
                    let credential = BasicCredential::new(b"test_user".to_vec());
                    // 2. Generate the corresponding signature key pair.
                    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
                        .expect("Failed to create signature key pair.");
                    // 3. Combine them into a credential-with-key structure.
                    let credential_with_key = CredentialWithKey {
                        credential: credential.into(),
                        signature_key: signature_keys.public().into(),
                    };
                    (credential_with_key, signature_keys)
                },
                |(credential_with_key, signature_keys)| {
                    // TIMED: This is the code block that will be measured.
                    // Create the KeyPackageBundle. The bundle includes the public KeyPackage
                    // and the corresponding private keys, which are stored securely.
                    let _key_package_bundle = KeyPackage::builder()
                        .build(ciphersuite, provider, &signature_keys, credential_with_key)
                        .expect("An unexpected error occurred during KeyPackage creation.");
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ─── Benchmark Runner ────────────────────────────────────────────────────────
fn run_all_benchmarks(c: &mut Criterion) {
    // ─── Objective 1 ─────────────────────────────────────────────────────
    benchmark_key_package_creation(c);
    // ─── Objective 2 ─────────────────────────────────────────────────────
    // ─── Objective 3 ─────────────────────────────────────────────────────
    // ─── Objective 4 ─────────────────────────────────────────────────────
    // ─── Objective 5 ─────────────────────────────────────────────────────
}

// Register the benchmark group with Criterion.
criterion_group!(benches, run_all_benchmarks);
// Generate the main function to run the benchmarks.
criterion_main!(benches);
