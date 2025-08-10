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
const GROUP_SIZES: &[usize] = &[2, 10, 50, 100];
// const GROUP_SIZES: &[usize] = &[100, 200, 300, 400, 500];
// const GROUP_SIZES: &[usize] = &[500, 600, 700, 800, 900, 1000];
// const GROUP_SIZES: &[usize] = &[100];

// ─── Helper Functions ────────────────────────────────────────────────────────
// Function to generate a credential with a signature key pair.
fn generate_credential_with_key(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm).expect("Error generating a signature key pair.");
    signature_keys
        .store(provider.storage())
        .expect("Error storing signature keys in key store.");
    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

// Function to generate a key package bundle.
fn generate_key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
}

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

// ─── 2. Group Creation ───────────────────────────────────────────────────────
// # Benchmark: Group Creation
// * Objective: Measures the total time to create a new n-member group, from the perspective
// * of the group creator. This includes creating the group and sequentially adding all other members.
fn benchmark_group_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("2. Group Creation");
    let provider = &OpenMlsRustCrypto::default();

    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        for &size in GROUP_SIZES {
            let benchmark_id = BenchmarkId::new(
                "CreateGroup",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                // BatchSize::PerIteration ensures that for every single
                // measurement, we run the full setup again, guaranteeing that we are always
                // benchmarking the creation of a brand new group.
                b.iter_batched(
                    || {
                        // SETUP: This part is not timed.
                        // We pre-generate all credentials and key packages for the n-1 members
                        // who will be added to the group.

                        // 1. Creator's (Alice's) identity.
                        let (alice_credential_with_key, alice_signer) =
                            generate_credential_with_key(
                                b"Alice".to_vec(),
                                ciphersuite.signature_algorithm(),
                                provider,
                            );

                        // 2. Group configuration.
                        let mls_group_create_config = MlsGroupCreateConfig::builder()
                            .ciphersuite(ciphersuite)
                            .build();

                        // 3. Identities for the other n-1 members.
                        let mut member_key_packages = Vec::with_capacity(size - 1);
                        for i in 2..=size {
                            let (member_credential, member_signer) = generate_credential_with_key(
                                format!("Member {}", i).into_bytes(),
                                ciphersuite.signature_algorithm(),
                                provider,
                            );
                            let key_package = generate_key_package(
                                ciphersuite,
                                provider,
                                &member_signer,
                                member_credential,
                            );
                            member_key_packages.push(key_package.key_package().clone());
                        }

                        (
                            alice_signer,
                            mls_group_create_config,
                            alice_credential_with_key,
                            member_key_packages,
                        )
                    },
                    |(
                        alice_signer,
                        mls_group_create_config,
                        alice_credential_with_key,
                        member_key_packages,
                    )| {
                        // TIMED: This is the code block that will be measured.
                        // 1. Alice creates the group, which initially only contains her.
                        let mut alice_group = MlsGroup::new(
                            provider,
                            &alice_signer,
                            &mls_group_create_config,
                            alice_credential_with_key,
                        )
                        .expect("Error creating group.");

                        // 2. Alice adds all other members.
                        if !member_key_packages.is_empty() {
                            alice_group
                                .add_members(provider, &alice_signer, &member_key_packages)
                                .expect("Error adding members.");
                            alice_group
                                .merge_pending_commit(provider)
                                .expect("Error merging commit after adding members.");
                        }
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

// ─── Benchmark Runner ────────────────────────────────────────────────────────
fn run_all_benchmarks(c: &mut Criterion) {
    // ─── Objective 1 ─────────────────────────────────────────────────────
    benchmark_key_package_creation(c);
    // ─── Objective 2 ─────────────────────────────────────────────────────
    benchmark_group_creation(c);
    // ─── Objective 3 ─────────────────────────────────────────────────────
    // ─── Objective 4 ─────────────────────────────────────────────────────
    // ─── Objective 5 ─────────────────────────────────────────────────────
}

// Register the benchmark group with Criterion.
criterion_group!(benches, run_all_benchmarks);
// Generate the main function to run the benchmarks.
criterion_main!(benches);
