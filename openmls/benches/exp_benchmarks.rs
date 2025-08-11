#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::{BatchSize, BenchmarkId, Criterion};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_pqc_crypto::OpenMlsPqcProvider;
// use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

// ─── Constants And Configuration ─────────────────────────────────────────────
// const GROUP_SIZES: &[usize] = &[2, 10, 50];
// const GROUP_SIZES: &[usize] = &[100, 200, 300, 400, 500];
// const GROUP_SIZES: &[usize] = &[500, 600, 700, 800, 900, 1000];
const GROUP_SIZES: &[usize] = &[1000];

const CIPHERSUITES_TO_TEST: &[Ciphersuite] = &[
    // Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    // Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44,
    // Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65,
    // Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SLHDSA_SHA2_128F,
    // Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
];

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
fn benchmark_key_package_creation(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("1. Key Package Creation");

    // Iterate over all supported ciphersuites to test each one.
    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
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
fn benchmark_group_creation(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("2. Group Creation");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
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
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
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

// ─── 3. Member Addtion ───────────────────────────────────────────────────────
// # Benchmark: Add Member (Sender)
// * Objective: Measures the time for an existing group member to create a Commit that
// * adds a new member to a group of size n.
fn benchmark_add_member_sender(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("3.1. Member Addition (Sender)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            // We are adding one member to a group of size-1 to reach size.
            let initial_size = size - 1;
            if initial_size == 0 {
                continue;
            } // Group must have at least one member.

            let benchmark_id = BenchmarkId::new(
                "AddMemberSender",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                // iter_batched with PerIteration is necessary because add_members modifies
                // the internal state of the MlsGroup by creating a pending commit.
                // Each run must start with a clean group state.
                b.iter_batched(
                    || {
                        // SETUP: Create a stable group of initial_size.
                        // 1. Create Alice's credential and signer.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );

                        // 2. Create the group configuration.
                        let mls_group_create_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();

                        // 3. Create the group.
                        let mut alice_group = MlsGroup::new(
                            provider,
                            &alice_signer,
                            &mls_group_create_config,
                            alice_credential,
                        )
                        .unwrap();

                        // 4. Add initial members.
                        if initial_size > 1 {
                            let mut key_packages_to_add = Vec::new();
                            for i in 2..=initial_size {
                                let (member_credential_with_key, member_signer) =
                                    generate_credential_with_key(
                                        format!("Member {}", i).into_bytes(),
                                        ciphersuite.signature_algorithm(),
                                        provider,
                                    );
                                let kp_bundle = generate_key_package(
                                    ciphersuite,
                                    provider,
                                    &member_signer,
                                    member_credential_with_key,
                                );
                                key_packages_to_add.push(kp_bundle.key_package().clone());
                            }
                            alice_group
                                .add_members(provider, &alice_signer, &key_packages_to_add)
                                .unwrap();
                            alice_group.merge_pending_commit(provider).unwrap();
                        }

                        // 5. Create the KeyPackage for the new member (Bob) who will be added.
                        let (bob_credential_with_key, bob_signer) = generate_credential_with_key(
                            b"bob".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        let bob_key_package = generate_key_package(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential_with_key,
                        );

                        (alice_group, alice_signer, bob_key_package)
                    },
                    |(mut group_creator, creator_signer, bob_key_package)| {
                        // TIMED: The cost of creating the Commit and Welcome message.
                        let _ = group_creator
                            .add_members(
                                provider,
                                &creator_signer,
                                &[bob_key_package.key_package().clone()],
                            )
                            .expect("Error adding member");

                        // Merging the pending commit for the commit creator is
                        // important to ensure that all changes are valid and applied.
                        group_creator
                            .merge_pending_commit(provider)
                            .expect("Error merging commit after adding member.");
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

// # Benchmark: Add Member (Receiver - New)
// * Objective: Measures the time for a new member to process a Welcome message and
// join a group, bringing it to size n.
fn benchmark_add_member_receiver_new(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("3.2. Member Addition (Receiver - New Member)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            if size < 2 {
                continue;
            } // A new member can only join a group of at least 1.
            let initial_size = size - 1;

            let benchmark_id = BenchmarkId::new(
                "AddMemberNewReceiver",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                b.iter_batched(
                    || {
                        // SETUP: Create a group of initial_size and a Welcome message for a new member.
                        // 1. Create Alice's credential and signer.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 2. Create the group configuration.
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        // 3. Create the group.
                        let mut alice_group =
                            MlsGroup::new(provider, &alice_signer, &group_config, alice_credential)
                                .unwrap();

                        // 4. Add initial members to the group.
                        // If initial_size is greater than 1, we add members to the group.
                        if initial_size > 1 {
                            let mut key_packages = Vec::new();
                            for i in 2..=initial_size {
                                let (member_credential_with_key, member_signer) =
                                    generate_credential_with_key(
                                        format!("Member {}", i).into_bytes(),
                                        ciphersuite.signature_algorithm(),
                                        provider,
                                    );
                                let kp = generate_key_package(
                                    ciphersuite,
                                    provider,
                                    &member_signer,
                                    member_credential_with_key,
                                );
                                key_packages.push(kp.key_package().clone());
                            }
                            alice_group
                                .add_members(provider, &alice_signer, &key_packages)
                                .unwrap();
                            alice_group.merge_pending_commit(provider).unwrap();
                        }

                        // 5. Create the new member's (Bob's) identity and generate the Welcome.
                        let (bob_credential_with_key, bob_signer) = generate_credential_with_key(
                            b"bob".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        let bob_key_package = generate_key_package(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential_with_key,
                        );

                        let (_, welcome, _) = alice_group
                            .add_members(
                                provider,
                                &alice_signer,
                                &[bob_key_package.key_package().clone()],
                            )
                            .unwrap();
                        alice_group.merge_pending_commit(provider).unwrap();

                        (
                            welcome,
                            group_config.join_config().clone(),
                            Some(alice_group.export_ratchet_tree().into()),
                        )
                    },
                    |(welcome, join_config, ratchet_tree)| {
                        // TIMED: Processing the Welcome message to create the group state.
                        let welcome_msg: MlsMessageIn = welcome.into();
                        let staged_welcome = StagedWelcome::new_from_welcome(
                            provider,
                            &join_config,
                            welcome_msg.into_welcome().unwrap(),
                            ratchet_tree,
                        )
                        .unwrap();

                        let _bob_group = staged_welcome.into_group(provider).unwrap();
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

// # Benchmark: Add Member (Receiver - Existing)
// * Objective: Measures the time for an existing member to process a Commit that
// * adds a new member, bringing the group to size n.
fn benchmark_add_member_receiver_existing(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("3.3. Member Addition (Receiver - Existing Member)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            if size < 3 {
                continue;
            } // Need at least one creator, one existing member, and one new member.
            let initial_size = size - 1;

            let benchmark_id = BenchmarkId::new(
                "AddMemberExistingReceiver",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                // iter_batched is critical because the timed routine modifies the state of
                // existing_member_group by merging a commit. Each measurement must
                // start from the state before the new member was added.
                b.iter_batched(
                    || {
                        // SETUP: Create a group with initial_size members.
                        // 1. Create Alice's credential and key pair
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 2. Create Bob's credential and key pair
                        let (bob_credential_with_key, bob_signer) = generate_credential_with_key(
                            b"Bob".to_vec(), // The new member
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 3. Create Charlie's credential and key pair
                        let (charlie_credential_with_key, charlie_signer) =
                            generate_credential_with_key(
                                b"Charlie".to_vec(), // The existing member
                                ciphersuite.signature_algorithm(),
                                provider,
                            );

                        // 4. Create Bob's key package
                        let bob_key_package = generate_key_package(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential_with_key,
                        );
                        // 5. Create Charlie's key package
                        let charlie_key_package = generate_key_package(
                            ciphersuite,
                            provider,
                            &charlie_signer,
                            charlie_credential_with_key.clone(),
                        );

                        // 6. Create group config and Alice's initial group
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        let mut alice_group = MlsGroup::new(
                            provider,
                            &alice_signer,
                            &group_config,
                            alice_credential.clone(),
                        )
                        .unwrap();

                        // 7. Establish Charlie in the group along with other initial members
                        let mut initial_members = vec![charlie_key_package.key_package().clone()];
                        for i in 3..=initial_size {
                            let (mem_cred, mem_signer) = generate_credential_with_key(
                                format!("Member {}", i).into_bytes(),
                                ciphersuite.signature_algorithm(),
                                provider,
                            );
                            let kp =
                                generate_key_package(ciphersuite, provider, &mem_signer, mem_cred);
                            initial_members.push(kp.key_package().clone());
                        }

                        let (_, welcome_for_charlie, _) = alice_group
                            .add_members(provider, &alice_signer, &initial_members)
                            .unwrap();
                        alice_group.merge_pending_commit(provider).unwrap();

                        // 8. Create a staged welcome for Charlie.
                        let welcome_msg: MlsMessageIn = welcome_for_charlie.into();
                        let staged_welcome = StagedWelcome::new_from_welcome(
                            provider,
                            group_config.join_config(),
                            welcome_msg.into_welcome().unwrap(),
                            Some(alice_group.export_ratchet_tree().into()),
                        );
                        // 9. Convert the staged welcome into a group for Charlie.
                        let charlie_group = staged_welcome
                            .expect("Error creating staged welcome.")
                            .into_group(provider)
                            .unwrap();

                        // 10. Create a commit for Charlie with Alice adding Bob to the group.
                        let (commit_for_charlie, _, _) = alice_group
                            .add_members(
                                provider,
                                &alice_signer,
                                &[bob_key_package.key_package().clone()],
                            )
                            .unwrap();

                        (charlie_group, commit_for_charlie)
                    },
                    |(mut existing_member_group, commit)| {
                        // TIMED: Processing the commit message.
                        let processed_message = existing_member_group
                            .process_message(provider, commit.into_protocol_message().unwrap())
                            .unwrap();

                        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                            processed_message.into_content()
                        {
                            existing_member_group
                                .merge_staged_commit(provider, *staged_commit)
                                .expect("Error merging staged commit");
                        } else {
                            panic!("Expected a StagedCommitMessage");
                        }
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

// ─── 4. Group Updates ────────────────────────────────────────────────────────
// # Benchmark: Self-Update (Sender)
// * Objective: Measures the time for a member in a group of size n to create a Commit
// * message by updating their own leaf node using .self_update()
fn benchmark_self_update_sender(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("4.1. Group Update (Sender - SelfUpdate)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            if size == 0 {
                continue;
            }

            let benchmark_id = BenchmarkId::new(
                "SelfUpdateSender",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                b.iter_batched(
                    || {
                        // SETUP: Create a group with size members.
                        // 1. Create Alice's credential and key package.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 2. Create the group configuration.
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        // 3. Create the group.
                        let mut alice_group =
                            MlsGroup::new(provider, &alice_signer, &group_config, alice_credential)
                                .expect("Error creating group for Alice.");

                        // 4. Add members to the group.
                        if size > 1 {
                            let mut members_to_add = Vec::new();
                            for i in 2..=size {
                                let (member_credential, member_signer) =
                                    generate_credential_with_key(
                                        format!("Member {}", i).into_bytes(),
                                        ciphersuite.signature_algorithm(),
                                        provider,
                                    );
                                let kp = generate_key_package(
                                    ciphersuite,
                                    provider,
                                    &member_signer,
                                    member_credential,
                                );
                                members_to_add.push(kp.key_package().clone());
                            }
                            alice_group
                                .add_members(provider, &alice_signer, &members_to_add)
                                .unwrap();
                            alice_group.merge_pending_commit(provider).unwrap();
                        }
                        (alice_group, alice_signer)
                    },
                    |(mut alice_group, alice_signer)| {
                        // TIMED: Perform the self-update.
                        let (_commit, _, _) = alice_group
                            .self_update(provider, &alice_signer, LeafNodeParameters::default())
                            .expect("Error creating self-update commit.")
                            .into_contents();
                        alice_group
                            .merge_pending_commit(provider)
                            .expect("Error merging self-update commit.");
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

// # Benchmark: Self-Update (Receiver)
// * Objective: Measures the time for an existing group member in a group of size n
// * to process a Commit message from another member's self-update.
fn benchmark_self_update_receiver(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("4.2. Group Update (Receiver - SelfUpdate)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            if size < 2 {
                continue;
            }

            let benchmark_id = BenchmarkId::new(
                "SelfUpdateReceiver",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                b.iter_batched(
                    || {
                        // SETUP: Create a group with size members and perform a self-update.
                        // 1. Create Alice's credential.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 2. Create Bob's credential and key package.
                        let (bob_credential, bob_signer) = generate_credential_with_key(
                            b"Bob".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        let bob_key_package = generate_key_package(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential,
                        );

                        // 3. Create group config and Alice's group.
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        let mut alice_group = MlsGroup::new(
                            provider,
                            &alice_signer,
                            &group_config,
                            alice_credential.clone(),
                        )
                        .expect("Error creating group for Alice.");

                        // 4. Add Bob and other initial members to Alice's group.
                        let mut members_to_add = vec![bob_key_package.key_package().clone()];
                        for i in 3..=size {
                            let (member_credential, member_signer) = generate_credential_with_key(
                                format!("Member {}", i).into_bytes(),
                                ciphersuite.signature_algorithm(),
                                provider,
                            );
                            let kp = generate_key_package(
                                ciphersuite,
                                provider,
                                &member_signer,
                                member_credential,
                            );
                            members_to_add.push(kp.key_package().clone());
                        }

                        let (_, welcome, _) = alice_group
                            .add_members(provider, &alice_signer, &members_to_add)
                            .unwrap();
                        alice_group.merge_pending_commit(provider).unwrap();

                        // 5. Create a staged welcome for Bob.
                        let staged_welcome = StagedWelcome::new_from_welcome(
                            provider,
                            group_config.join_config(),
                            welcome.into_welcome().unwrap(),
                            Some(alice_group.export_ratchet_tree().into()),
                        )
                        .unwrap();
                        // 6. Create Bob's group.
                        let bob_group = staged_welcome.into_group(provider).unwrap();

                        // 7. Alice performs a self-update.
                        let (commit_message, _, _) = alice_group
                            .self_update(provider, &alice_signer, LeafNodeParameters::default())
                            .unwrap()
                            .into_contents();
                        (bob_group, commit_message)
                    },
                    |(mut bob_group, commit_message)| {
                        let processed = bob_group
                            .process_message(
                                provider,
                                commit_message.into_protocol_message().unwrap(),
                            )
                            .expect("Error processing update commit.");
                        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                            processed.into_content()
                        {
                            bob_group
                                .merge_staged_commit(provider, *staged_commit)
                                .expect("Error merging staged commit.");
                        } else {
                            panic!("Expected a StagedCommitMessage");
                        }
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

// ─── 5. Member Removal ───────────────────────────────────────────────────────
// # Benchmark: Remove Member (Sender)
// * Objective: Measures the time for a member in a group of size n to create a Commit
// * that removes another member from the group.
fn benchmark_remove_member_sender(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("5.1. Member Removal (Sender)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            if size < 2 {
                continue;
            }

            let benchmark_id = BenchmarkId::new(
                "RemoveMemberSender",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                b.iter_batched(
                    || {
                        // SETUP: Create a group with size members.
                        // 1. Create Alice's key package.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 2. Create the group.
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        let mut alice_group =
                            MlsGroup::new(provider, &alice_signer, &group_config, alice_credential)
                                .expect("Error creating group for Alice.");

                        // 3. Add initial members.
                        if size > 1 {
                            let mut members_to_add = Vec::new();
                            for i in 2..=size {
                                let (member_credential, member_signer) =
                                    generate_credential_with_key(
                                        format!("Member {}", i).into_bytes(),
                                        ciphersuite.signature_algorithm(),
                                        provider,
                                    );
                                let kp = generate_key_package(
                                    ciphersuite,
                                    provider,
                                    &member_signer,
                                    member_credential,
                                );
                                members_to_add.push(kp.key_package().clone());
                            }
                            alice_group
                                .add_members(provider, &alice_signer, &members_to_add)
                                .unwrap();
                            alice_group.merge_pending_commit(provider).unwrap();
                        }
                        // 4. Select the last member to remove.
                        let leaf_index_to_remove = LeafNodeIndex::new((size - 1) as u32);
                        (alice_group, alice_signer, leaf_index_to_remove)
                    },
                    |(mut alice_group, alice_signer, leaf_index_to_remove)| {
                        alice_group
                            .remove_members(provider, &alice_signer, &[leaf_index_to_remove])
                            .expect("Error removing member.");
                        alice_group
                            .merge_pending_commit(provider)
                            .expect("Error merging removal commit.");
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
}

// # Benchmark: Remove Member (Receiver)
// * Objective: Measures the time for a remaining group member to process a Commit
// * that removes another member from a group of original size n.
fn benchmark_remove_member_receiver(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("5.2. Member Removal (Receiver)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            // Need at least 3 members: remover (Alice), removed (Charlie), and receiver (Bob).
            if size < 3 {
                continue;
            }

            let benchmark_id = BenchmarkId::new(
                "RemoveMemberReceiver",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                b.iter_with_setup(
                    || {
                        // SETUP: Create a stable group with two members, Alice (updater) and Bob (receiver).
                        // Then, have Alice create a removal commit for Bob to process.

                        // 1. Identities for Alice and Bob.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        let (credential, bob_signer) = generate_credential_with_key(
                            b"Bob".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        let bob_key_package =
                            generate_key_package(ciphersuite, provider, &bob_signer, credential);

                        // 2. Alice creates the group and adds Bob.
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        let mut alice_group =
                            MlsGroup::new(provider, &alice_signer, &group_config, alice_credential)
                                .expect("Error creating group for Alice.");

                        let (_, welcome, _) = alice_group
                            .add_members(
                                provider,
                                &alice_signer,
                                &[bob_key_package.key_package().clone()],
                            )
                            .unwrap();
                        alice_group.merge_pending_commit(provider).unwrap();

                        // 3. Bob joins the group using the Welcome message.
                        let welcome_msg: MlsMessageIn = welcome.into();
                        let staged_welcome = StagedWelcome::new_from_welcome(
                            provider,
                            group_config.join_config(),
                            welcome_msg.into_welcome().unwrap(),
                            Some(alice_group.export_ratchet_tree().into()),
                        )
                        .unwrap();
                        let mut bob_group = staged_welcome.into_group(provider).unwrap();

                        // (If size > 2, add remaining members and have Bob process the commits to stay in sync)
                        if size > 2 {
                            let mut members_to_add = Vec::new();
                            for i in 3..=size {
                                let (member_credential, member_signer) =
                                    generate_credential_with_key(
                                        format!("Member {}", i).into_bytes(),
                                        ciphersuite.signature_algorithm(),
                                        provider,
                                    );
                                let kp = generate_key_package(
                                    ciphersuite,
                                    provider,
                                    &member_signer,
                                    member_credential,
                                );
                                members_to_add.push(kp.key_package().clone());
                            }
                            let (commit, _, _) = alice_group
                                .add_members(provider, &alice_signer, &members_to_add)
                                .unwrap();
                            alice_group.merge_pending_commit(provider).unwrap();

                            let processed = bob_group
                                .process_message(provider, commit.into_protocol_message().unwrap())
                                .unwrap();
                            if let ProcessedMessageContent::StagedCommitMessage(sc) =
                                processed.into_content()
                            {
                                bob_group.merge_staged_commit(provider, *sc).unwrap();
                            }
                        }

                        // 4. Alice removes the last member ("Charlie")
                        let charlie_leaf_index = LeafNodeIndex::new((size - 1) as u32);
                        let (commit_for_removal, _, _) = alice_group
                            .remove_members(provider, &alice_signer, &[charlie_leaf_index])
                            .unwrap();

                        (bob_group, commit_for_removal)
                    },
                    |(mut bob_group, commit_for_removal)| {
                        // TIMED: Bob processes the commit that removes another member.
                        let processed = bob_group
                            .process_message(
                                provider,
                                commit_for_removal.into_protocol_message().unwrap(),
                            )
                            .expect("Error processing removal commit.");

                        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                            processed.into_content()
                        {
                            bob_group
                                .merge_staged_commit(provider, *staged_commit)
                                .expect("Error merging staged commit.");
                        } else {
                            panic!("Expected a StagedCommitMessage");
                        }
                    },
                );
            });
        }
    }
    group.finish();
}

// ─── 6. Application Messaging ────────────────────────────────────────────────
// # Benchmark: Send Application Message
// * Objective: Measures the time it takes for a group member to create and encrypt an
// * application message for a group of size n. This tests the "hot path" for sending data.
// * Measure any impact of digital signature schemes on performance.
fn benchmark_send_application_message(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("6.1. Application Message (Send)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            if size == 0 {
                continue;
            }

            let benchmark_id = BenchmarkId::new(
                "SendMessage",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                b.iter_with_setup(
                    || {
                        // SETUP: Create a stable group of size members.
                        // We will measure the time it takes for the creator (Alice) to send a message.
                        // 1. Create Alice's credential and key pair.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 2. Create the group configuration.
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        // 3. Create the group.
                        let mut alice_group =
                            MlsGroup::new(provider, &alice_signer, &group_config, alice_credential)
                                .unwrap();

                        // 4. Add members to the group.
                        if size > 1 {
                            let mut members_to_add = Vec::new();
                            for i in 2..=size {
                                let (member_credential, member_signer) =
                                    generate_credential_with_key(
                                        format!("Member {}", i).into_bytes(),
                                        ciphersuite.signature_algorithm(),
                                        provider,
                                    );
                                let kp = generate_key_package(
                                    ciphersuite,
                                    provider,
                                    &member_signer,
                                    member_credential,
                                );
                                members_to_add.push(kp.key_package().clone());
                            }
                            let (_, _welcome, _) = alice_group
                                .add_members(provider, &alice_signer, &members_to_add)
                                .unwrap();
                            alice_group.merge_pending_commit(provider).unwrap();
                        }

                        // 5. Create the message payload.
                        let message_payload = b"This is a test message.";
                        (alice_group, alice_signer, message_payload)
                    },
                    |(mut alice_group, alice_signer, message_payload)| {
                        // TIMED: The cost of deriving the key and encrypting the message.
                        let _ = alice_group
                            .create_message(provider, &alice_signer, message_payload)
                            .expect("Error creating application message.");
                    },
                );
            });
        }
    }
    group.finish();
}

// # Benchmark: Receive Application Message
// * Objective: Measures the time it takes for a group member to process and decrypt
// * an incoming application message in a group of size n.
fn benchmark_receive_application_message(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    let mut group = c.benchmark_group("6.2. Application Message (Receive)");

    for &ciphersuite in CIPHERSUITES_TO_TEST.iter() {
        for &size in GROUP_SIZES {
            if size < 2 {
                continue;
            } // Need a sender and a receiver.

            let benchmark_id = BenchmarkId::new(
                "ReceiveMessage",
                format!("size={:04}, cs={:?}", size, ciphersuite),
            );

            group.bench_function(benchmark_id, move |b| {
                b.iter_with_setup(
                    || {
                        // SETUP: Create a stable group of size, have Alice send a message,
                        // and prepare for Bob to receive it.
                        // 1. Create Alice's credential and key pair.
                        let (alice_credential, alice_signer) = generate_credential_with_key(
                            b"Alice".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        // 2. Create Bob's credential and key pair.
                        let (bob_credential, bob_signer) = generate_credential_with_key(
                            b"Bob".to_vec(),
                            ciphersuite.signature_algorithm(),
                            provider,
                        );
                        let bob_key_package = generate_key_package(
                            ciphersuite,
                            provider,
                            &bob_signer,
                            bob_credential,
                        );

                        // 3. Create the group configuration.
                        let group_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();
                        // 4. Create Alice's group.
                        let mut alice_group =
                            MlsGroup::new(provider, &alice_signer, &group_config, alice_credential)
                                .unwrap();

                        // Add Bob and any other members
                        let mut key_packages_to_add = vec![bob_key_package.key_package().clone()];
                        for i in 3..=size {
                            let (member_credential, member_signer) = generate_credential_with_key(
                                format!("Member {}", i).into_bytes(),
                                ciphersuite.signature_algorithm(),
                                provider,
                            );
                            let kp = generate_key_package(
                                ciphersuite,
                                provider,
                                &member_signer,
                                member_credential,
                            );
                            key_packages_to_add.push(kp.key_package().clone());
                        }

                        let (_, welcome, _) = alice_group
                            .add_members(provider, &alice_signer, &key_packages_to_add)
                            .unwrap();
                        alice_group.merge_pending_commit(provider).unwrap();

                        // 5. Create a staged welcome for Bob.
                        let welcome_msg: MlsMessageIn = welcome.into();
                        let staged_welcome = StagedWelcome::new_from_welcome(
                            provider,
                            group_config.join_config(),
                            welcome_msg.into_welcome().unwrap(),
                            Some(alice_group.export_ratchet_tree().into()),
                        )
                        .unwrap();
                        let bob_group = staged_welcome.into_group(provider).unwrap();

                        // 6. Alice creates an application message to send to Bob.
                        // This is the message that Bob will receive.
                        let application_message = alice_group
                            .create_message(provider, &alice_signer, b"Hello, Bob!")
                            .unwrap();

                        (bob_group, application_message)
                    },
                    |(mut bob_group, application_message)| {
                        // TIMED: The cost of decrypting and verifying the message.
                        let _processed_message = bob_group
                            .process_message(
                                provider,
                                application_message.into_protocol_message().unwrap(),
                            )
                            .expect("Error processing application message.");
                    },
                );
            });
        }
    }
    group.finish();
}

// ─── Benchmark Runner ────────────────────────────────────────────────────────
fn run_all_benchmarks(c: &mut Criterion) {
    // let provider = &OpenMlsRustCrypto::default();
    let provider = &OpenMlsPqcProvider::default();
    // ─── Objective 1 ─────────────────────────────────────────────────────
    benchmark_key_package_creation(c, provider);
    // ─── Objective 2 ─────────────────────────────────────────────────────
    benchmark_group_creation(c, provider);
    // ─── Objective 3 ─────────────────────────────────────────────────────
    benchmark_add_member_sender(c, provider);
    benchmark_add_member_receiver_new(c, provider);
    benchmark_add_member_receiver_existing(c, provider);
    // ─── Objective 4 ─────────────────────────────────────────────────────
    benchmark_self_update_sender(c, provider);
    benchmark_self_update_receiver(c, provider);
    // ─── Objective 5 ─────────────────────────────────────────────────────
    benchmark_remove_member_sender(c, provider);
    benchmark_remove_member_receiver(c, provider);
    // ─── Objective 6 ─────────────────────────────────────────────────────
    benchmark_send_application_message(c, provider);
    benchmark_receive_application_message(c, provider);
}

// Register the benchmark group with Criterion.
criterion_group!(benches, run_all_benchmarks);
// Generate the main function to run the benchmarks.
criterion_main!(benches);
