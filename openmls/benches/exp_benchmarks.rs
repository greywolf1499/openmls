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
use std::time::Instant;

// ─── Constants And Configuration ─────────────────────────────────────────────
const GROUP_SIZES: &[usize] = &[2, 10, 50, 100];
// const GROUP_SIZES: &[usize] = &[100, 200, 300, 400, 500];
// const GROUP_SIZES: &[usize] = &[500, 600, 700, 800, 900, 1000];
// const GROUP_SIZES: &[usize] = &[100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
// const GROUP_SIZES: &[usize] = &[1000];

const CIPHERSUITES_TO_TEST: &[Ciphersuite] = &[
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    // Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
];

const MAX_GROUP_SIZE: usize = 1000;

// ─── Benchmark Fixtures And Setup ────────────────────────────────────────────
//
struct BenchmarkFixture {
    provider: OpenMlsPqcProvider,
    ciphersuite: Ciphersuite,
    new_member_kp_bundle: KeyPackageBundle,
    member_pool: Vec<KeyPackageBundle>,
}

fn create_member(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    id: &[u8],
) -> (CredentialWithKey, SignatureKeyPair, KeyPackageBundle) {
    let credential = BasicCredential::new(id.to_vec());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .expect("Error generating a signature key pair.");
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };
    let key_package_bundle = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            credential_with_key.clone(),
        )
        .expect("Error creating key package bundle.");
    (credential_with_key, signature_keys, key_package_bundle)
}

// Generate all the key material we will need for the entire suite of benchmarks
fn setup_fixture(ciphersuite: Ciphersuite) -> BenchmarkFixture {
    println!(
        "\nSetting up ONE-TIME fixture for ciphersuite: {:?}",
        ciphersuite
    );
    let start = Instant::now();

    let provider = OpenMlsPqcProvider::default();

    // Pre-generate the key package for the "new member" (e.g., Bob)
    let (_, _, new_member_kp_bundle) = create_member(ciphersuite, &provider, b"new_member");

    // Pre-generate a pool of members to build groups from.
    // This is the most expensive part, so we only run it ONCE.
    println!(
        "Generating member pool of size {}... (This may take a moment)",
        MAX_GROUP_SIZE
    );
    let member_pool: Vec<KeyPackageBundle> = (0..MAX_GROUP_SIZE)
        .map(|i| {
            let id = format!("member_{}", i);
            let (_, _, kp_bundle) = create_member(ciphersuite, &provider, id.as_bytes());
            kp_bundle
        })
        .collect();

    println!("Fixture setup complete in {:.2?}.\n", start.elapsed());

    BenchmarkFixture {
        provider,
        ciphersuite,
        new_member_kp_bundle,
        member_pool,
    }
}

// ─── 1. Keypackage Creation ──────────────────────────────────────────────────
// # Benchmark: Key Package Creation
// * Objective: Measures the time for a single user to generate their cryptographic identity
// * and create a KeyPackageBundle. This captures the foundational per-user cost before joining any group.
fn benchmark_key_package_creation(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("1. Key Package Creation");
    let ciphersuite = fixture.ciphersuite;

    let benchmark_id = BenchmarkId::new("CreateBundle", format!("{:?}", ciphersuite));

    group.bench_function(benchmark_id, move |b| {
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
                    .build(
                        ciphersuite,
                        &fixture.provider,
                        &signature_keys,
                        credential_with_key,
                    )
                    .expect("An unexpected error occurred during KeyPackage creation.");
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ─── 2. Group Creation ───────────────────────────────────────────────────────
// # Benchmark: Group Creation
// * Objective: Measures the total time to create a new n-member group, from the perspective
// * of the group creator. This includes creating the group and sequentially adding all other members.
fn benchmark_group_creation(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("2. Group Creation");
    let ciphersuite = fixture.ciphersuite;

    for &size in GROUP_SIZES {
        let benchmark_id = BenchmarkId::new(
            "CreateGroup",
            format!("size={:04}, cs={:?}", size, ciphersuite),
        );

        group.bench_function(benchmark_id, |b| {
            b.iter_batched(
                || {
                    // SETUP: This part is not timed.

                    // 1. Creator's (Alice's) identity.
                    let (alice_credential_with_key, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");

                    // 2. Group configuration.
                    let mls_group_create_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // 3. Identities for the other n-1 members.
                    let member_key_packages: Vec<KeyPackage> = fixture
                        .member_pool
                        .iter()
                        .take(size - 1)
                        .map(|kb| kb.key_package().clone())
                        .collect();

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
                        &fixture.provider,
                        &alice_signer,
                        &mls_group_create_config,
                        alice_credential_with_key,
                    )
                    .expect("Error creating group.");

                    // 2. Alice adds all other members.
                    if !member_key_packages.is_empty() {
                        alice_group
                            .add_members(&fixture.provider, &alice_signer, &member_key_packages)
                            .expect("Error adding members.");
                        alice_group
                            .merge_pending_commit(&fixture.provider)
                            .expect("Error merging commit after adding members.");
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// ─── 3. Member Addtion ───────────────────────────────────────────────────────
// # Benchmark: Add Member (Sender)
// * Objective: Measures the time for an existing group member to create a Commit that
// * adds a new member to a group of size n.
fn benchmark_add_member_sender(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("3.1. Member Addition (Sender)");
    let ciphersuite = fixture.ciphersuite;

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

        group.bench_function(benchmark_id, |b| {
            // Each run must start with a clean group state.
            b.iter_batched(
                || {
                    // SETUP: Create a stable group of initial_size.
                    // 1. Create Alice's credential and signer.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");

                    // 2. Create the group configuration.
                    let mls_group_create_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // 3. Create the group.
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &mls_group_create_config,
                        alice_credential,
                    )
                    .unwrap();

                    // 4. Add initial members.
                    if initial_size > 1 {
                        let members_to_add: Vec<KeyPackage> = fixture
                            .member_pool
                            .iter()
                            .take(initial_size - 1)
                            .map(|bundle| bundle.key_package().clone())
                            .collect();
                        alice_group
                            .add_members(&fixture.provider, &alice_signer, &members_to_add)
                            .unwrap();
                        alice_group.merge_pending_commit(&fixture.provider).unwrap();
                    }

                    // 5. Take the new member's key package from the fixture.
                    let new_member_kp = fixture.new_member_kp_bundle.key_package().clone();

                    (alice_group, alice_signer, new_member_kp)
                },
                |(mut group_creator, creator_signer, new_member_kp)| {
                    // TIMED: The cost of creating the Commit and Welcome message.
                    let _ = group_creator
                        .add_members(&fixture.provider, &creator_signer, &[new_member_kp])
                        .expect("Error adding member");

                    // Merging the pending commit for the commit creator is
                    // important to ensure that all changes are valid and applied.
                    group_creator
                        .merge_pending_commit(&fixture.provider)
                        .expect("Error merging commit after adding member.");
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// # Benchmark: Add Member (Receiver - New)
// * Objective: Measures the time for a new member to process a Welcome message and
// * join a group, bringing it to size n.
fn benchmark_add_member_receiver_new(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("3.2. Member Addition (Receiver - New Member)");
    let ciphersuite = fixture.ciphersuite;

    for &size in GROUP_SIZES {
        if size < 2 {
            continue;
        } // A new member can only join a group of at least 1.
        let initial_size = size - 1;

        let benchmark_id = BenchmarkId::new(
            "AddMemberNewReceiver",
            format!("size={:04}, cs={:?}", size, ciphersuite),
        );

        group.bench_function(benchmark_id, |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a group of initial_size and a Welcome message for a new member.
                    // 1. Create Alice's credential and signer.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");
                    // 2. Create the group configuration.
                    let group_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();
                    // 3. Create the group.
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &group_config,
                        alice_credential,
                    )
                    .unwrap();

                    // 4. Add initial members to the group from the fixture's pool.
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

                    // 5. Create the new member's (Bob's) identity and generate the Welcome.
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_new_member");

                    // 6. Have Alice add the new member. This is the action that creates the Welcome message.
                    let (_, welcome, _) = alice_group
                        .add_members(
                            &fixture.provider,
                            &alice_signer,
                            &[bob_key_package.key_package().clone()],
                        )
                        .unwrap();

                    // 7. Merge the pending commit to finalize the group state.
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // The ratchet tree is needed to process the Welcome message.
                    let ratchet_tree = Some(alice_group.export_ratchet_tree().into());

                    // The setup returns the essential items for the timed routine.
                    (welcome, group_config, ratchet_tree)
                },
                |(welcome, group_config, ratchet_tree)| {
                    // TIMED: Processing the Welcome message to create the group state.
                    let welcome_msg: MlsMessageIn = welcome.into();
                    let staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        welcome_msg.into_welcome().unwrap(),
                        ratchet_tree,
                    )
                    .unwrap();

                    // The actual group creation from the Welcome.
                    let _bob_group = staged_welcome.into_group(&fixture.provider).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

// # Benchmark: Add Member (Receiver - Existing)
// * Objective: Measures the time for an existing member to process a Commit that
// * adds a new member, bringing the group to size n.
fn benchmark_add_member_receiver_existing(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("3.3. Member Addition (Receiver - Existing Member)");
    let ciphersuite = fixture.ciphersuite;

    for &size in GROUP_SIZES {
        // We need at least 3 members:
        // 1. The creator (Alice)
        // 2. The existing member processing the commit (Charlie)
        // 3. The new member being added (Bob)
        if size < 3 {
            continue;
        }
        let initial_size = size - 1;

        let benchmark_id = BenchmarkId::new(
            "AddMemberExistingReceiver",
            format!("size={:04}, cs={:?}", size, ciphersuite),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a group with initial_size members.
                    // 1. Create the group creator, Alice.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_creator");

                    // 2. Create Bob's credential and key pair
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_member");

                    // 3. Create Charlie's credential and key pair
                    let (_, _, charlie_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"charlie_member");

                    // 4. Create group config and Alice's initial group
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

                    // 5. Establish Charlie in the group along with other initial members
                    let mut members_to_add = vec![charlie_key_package.key_package().clone()];
                    members_to_add.extend(
                        fixture
                            .member_pool
                            .iter()
                            .take(initial_size - 2)
                            .map(|bundle| bundle.key_package().clone()),
                    );

                    let (_, welcome_for_charlie, _) = alice_group
                        .add_members(&fixture.provider, &alice_signer, &members_to_add)
                        .unwrap();
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // 6. Create a staged welcome for Charlie.
                    let welcome_msg: MlsMessageIn = welcome_for_charlie.into();
                    let staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        welcome_msg.into_welcome().unwrap(),
                        Some(alice_group.export_ratchet_tree().into()),
                    );
                    // 7. Convert the staged welcome into a group for Charlie.
                    let charlie_group = staged_welcome
                        .expect("Error creating staged welcome.")
                        .into_group(&fixture.provider)
                        .unwrap();

                    // 8. Create a commit for Charlie with Alice adding Bob to the group.
                    let (commit_to_process, _, _) = alice_group
                        .add_members(
                            &fixture.provider,
                            &alice_signer,
                            &[bob_key_package.key_package().clone()],
                        )
                        .unwrap();

                    // 9. Return Charlie's group and the commit he needs to process.
                    (charlie_group, commit_to_process)
                },
                |(mut existing_member_group, commit)| {
                    // TIMED: Processing the commit message.
                    // An existing member processes a commit that adds a new member.
                    let processed_message = existing_member_group
                        .process_message(&fixture.provider, commit.into_protocol_message().unwrap())
                        .unwrap();

                    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                        processed_message.into_content()
                    {
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

// ─── 4. Group Updates ────────────────────────────────────────────────────────
// # Benchmark: Self-Update (Sender)
// * Objective: Measures the time for a member in a group of size n to create a Commit
// * message by updating their own leaf node using .self_update()
fn benchmark_self_update_sender(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("4.1. Group Update (Sender - SelfUpdate)");
    let ciphersuite = fixture.ciphersuite;

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
                    // 1. Create the member who will perform the update ("Alice").
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_updater");

                    // 2. Create the group configuration.
                    let group_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // 3. Alice creates the group, initially containing only herself.
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &group_config,
                        alice_credential,
                    )
                    .expect("Error creating group for Alice.");

                    // 4. Add the other "size - 1" members from the pre-computed pool.
                    if size > 1 {
                        // REFACTORED: Pull members from the pool instead of generating them.
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

                    // 5. Return the fully formed group and Alice's keys for the timed routine.
                    (alice_group, alice_signer)
                },
                |(mut alice_group, alice_signer)| {
                    // TIMED: Perform the self-update.
                    // We measure the cost of creating a Commit message.
                    let (_commit, _welcome, _staged_commit) = alice_group
                        .self_update(
                            &fixture.provider,
                            &alice_signer,
                            LeafNodeParameters::default(),
                        )
                        .expect("Error creating self-update commit.")
                        .into_contents();
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

// # Benchmark: Self-Update (Receiver)
// * Objective: Measures the time for an existing group member in a group of size n
// * to process a Commit message from another member's self-update.
fn benchmark_self_update_receiver(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("4.2. Group Update (Receiver - SelfUpdate)");
    let ciphersuite = fixture.ciphersuite;

    for &size in GROUP_SIZES {
        // We need at least two members: one to send the update, one to receive it.
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
                    // SETUP: Efficiently create two synchronized groups (Alice's and Bob's)
                    // and then have Alice generate a self-update commit for Bob to process.
                    // 1. Create Alice's credential.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_updater");

                    // 2. Create Bob's credential and key package.
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_updater");

                    // 3. Create group config and Alice's group.
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
                    .expect("Error creating group for Alice.");

                    // 4. Add Bob and other initial members to Alice's group.
                    let mut members_to_add = vec![bob_key_package.key_package().clone()];
                    members_to_add.extend(
                        fixture
                            .member_pool
                            .iter()
                            .take(size - 2) // Take the rest needed for the group size
                            .map(|kb| kb.key_package().clone()),
                    );

                    let (_, welcome, _) = alice_group
                        .add_members(&fixture.provider, &alice_signer, &members_to_add)
                        .unwrap();
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // 5. Create a staged welcome for Bob.
                    let staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        welcome.into_welcome().unwrap(),
                        Some(alice_group.export_ratchet_tree().into()),
                    )
                    .unwrap();

                    // 6. Create Bob's group.
                    let bob_group = staged_welcome.into_group(&fixture.provider).unwrap();

                    // 7. Alice performs a self-update.
                    let (commit_message, _, _) = alice_group
                        .self_update(
                            &fixture.provider,
                            &alice_signer,
                            LeafNodeParameters::default(),
                        )
                        .unwrap()
                        .into_contents();
                    (bob_group, commit_message)
                },
                |(mut bob_group, commit_message)| {
                    // TIMED: Bob processes Alice's self-update commit.
                    let processed = bob_group
                        .process_message(
                            &fixture.provider,
                            commit_message.into_protocol_message().unwrap(),
                        )
                        .expect("Error processing update commit.");
                    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                        processed.into_content()
                    {
                        bob_group
                            .merge_staged_commit(&fixture.provider, *staged_commit)
                            .expect("Error merging staged commit.");
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

// ─── 5. Member Removal ───────────────────────────────────────────────────────
// # Benchmark: Remove Member (Sender)
// * Objective: Measures the time for a member in a group of size n to create a Commit
// * that removes another member from the group.
fn benchmark_remove_member_sender(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("5.1. Member Removal (Sender)");
    let ciphersuite = fixture.ciphersuite;

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
                    // 1. Create the member who will perform the removal ("Alice").
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_remover");

                    // 2. Create the group configuration.
                    let group_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // 3. Alice creates the group, initially containing only herself.
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &group_config,
                        alice_credential,
                    )
                    .expect("Error creating group for Alice.");

                    // 4. Add initial members.
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

                    // 5. Select the last member to remove.
                    let leaf_index_to_remove = LeafNodeIndex::new((size - 1) as u32);

                    // 6. Return the group, the remover's keys, and the target for removal.
                    (alice_group, alice_signer, leaf_index_to_remove)
                },
                |(mut alice_group, alice_signer, leaf_index_to_remove)| {
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

// # Benchmark: Remove Member (Receiver)
// * Objective: Measures the time for a remaining group member to process a Commit
// * that removes another member from a group of original size n.
fn benchmark_remove_member_receiver(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("5.2. Member Removal (Receiver)");
    let ciphersuite = fixture.ciphersuite;

    for &size in GROUP_SIZES {
        // Need at least 3 members: remover (Alice), removed (Charlie), and receiver (Bob).
        // One to remove, one to be removed, and one to process the removal.
        if size < 3 {
            continue;
        }

        let benchmark_id = BenchmarkId::new(
            "RemoveMemberReceiver",
            format!("size={:04}, cs={:?}", size, ciphersuite),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a stable group with two members, Alice (updater) and Bob (receiver).
                    // Then, have Alice create a removal commit for Bob to process.

                    // 1a. Create the member who will perform the removal ("Alice").
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_remover");

                    // 1b. Create the member who will be removed ("Bob").
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_receiver");

                    // 1c. Create the member who will process the removal ("Charlie").
                    let (charlie_credential, _, charlie_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"charlie_receiver");

                    // 2. Alice creates the group.
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

                    // 3. Add the other "size - 3" members from the pre-computed pool.
                    let mut members_to_add = vec![
                        bob_key_package.key_package().clone(),
                        charlie_key_package.key_package().clone(),
                    ];

                    members_to_add.extend(
                        fixture
                            .member_pool
                            .iter()
                            .take(size - 3)
                            .map(|kb| kb.key_package().clone()),
                    );

                    // 4. Alice adds all members to the group.
                    let (_, welcome, _) = alice_group
                        .add_members(&fixture.provider, &alice_signer, &members_to_add)
                        .unwrap();
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // 5. Create Bob's synchronized group instance by processing the Welcome.
                    let bob_welcome_in: MlsMessageIn = welcome.into();
                    let bob_staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        bob_welcome_in.into_welcome().unwrap(),
                        Some(alice_group.export_ratchet_tree().into()),
                    );
                    let bob_group = bob_staged_welcome
                        .expect("Error creating staged welcome for Bob.")
                        .into_group(&fixture.provider)
                        .unwrap();

                    // 7. Now that groups are synced, Alice removes Charlie.
                    // We need to find Charlie's leaf index in Alice's group view.
                    let charlie_leaf_index = alice_group
                        .members()
                        .find(|m| m.credential == charlie_credential.credential)
                        .unwrap()
                        .index;
                    let (commit_for_removal, _, _) = alice_group
                        .remove_members(&fixture.provider, &alice_signer, &[charlie_leaf_index])
                        .unwrap();

                    (bob_group, commit_for_removal)
                },
                |(mut bob_group, commit_for_removal)| {
                    // TIMED: Bob processes the commit that removes another member.
                    let processed = bob_group
                        .process_message(
                            &fixture.provider,
                            commit_for_removal.into_protocol_message().unwrap(),
                        )
                        .expect("Error processing removal commit.");

                    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                        processed.into_content()
                    {
                        bob_group
                            .merge_staged_commit(&fixture.provider, *staged_commit)
                            .expect("Error merging staged commit.");
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

// ─── 6. Application Messaging ────────────────────────────────────────────────
// # Benchmark: Send Application Message
// * Objective: Measures the time it takes for a group member to create and encrypt an
// * application message for a group of size n. This tests the "hot path" for sending data.
// * Measure any impact of digital signature schemes on performance.
fn benchmark_send_application_message(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("6.1. Application Message (Send)");
    let ciphersuite = fixture.ciphersuite;

    for &size in GROUP_SIZES {
        if size < 2 {
            // Need a sender and a receiver.
            continue;
        }

        let benchmark_id = BenchmarkId::new(
            "SendMessage",
            format!("size={:04}, cs={:?}", size, ciphersuite),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a stable group of size members.
                    // We will measure the time it takes for the creator (Alice) to send a message.
                    // 1. Create the sender, Alice.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_sender");

                    // 2. Create the group configuration.
                    let group_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // 3. Create the group.
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &group_config,
                        alice_credential,
                    )
                    .unwrap();

                    // 4. Add the other "size - 1" members from the pool.
                    if size > 1 {
                        let members_to_add: Vec<KeyPackage> = fixture
                            .member_pool
                            .iter()
                            .take(size - 1)
                            .map(|kb| kb.key_package().clone())
                            .collect();

                        let (_, _welcome, _) = alice_group
                            .add_members(&fixture.provider, &alice_signer, &members_to_add)
                            .unwrap();
                        alice_group.merge_pending_commit(&fixture.provider).unwrap();
                    }

                    // 5. Create the message payload.
                    let message_payload = b"This is a test message.";
                    (alice_group, alice_signer, message_payload)
                },
                |(mut alice_group, alice_signer, message_payload)| {
                    // TIMED: The cost of deriving the key and encrypting the message.
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

// # Benchmark: Receive Application Message
// * Objective: Measures the time it takes for a group member to process and decrypt
// * an incoming application message in a group of size n.
fn benchmark_receive_application_message(c: &mut Criterion, fixture: &BenchmarkFixture) {
    let mut group = c.benchmark_group("6.2. Application Message (Receive)");
    let ciphersuite = fixture.ciphersuite;

    for &size in GROUP_SIZES {
        if size < 2 {
            continue;
        } // Need a sender and a receiver.

        let benchmark_id = BenchmarkId::new(
            "ReceiveMessage",
            format!("size={:04}, cs={:?}", size, ciphersuite),
        );

        group.bench_function(benchmark_id, move |b| {
            b.iter_batched(
                || {
                    // SETUP: Create a stable group of size, have Alice send a message,
                    // and prepare for Bob to receive it.
                    // 1. Create the sender, Alice.
                    let (alice_credential, alice_signer, _) =
                        create_member(ciphersuite, &fixture.provider, b"alice_sender");

                    // 2. Create Bob's member.
                    let (_, _, bob_key_package) =
                        create_member(ciphersuite, &fixture.provider, b"bob_receiver");

                    // 3. Create the group configuration.
                    let group_config = MlsGroupCreateConfig::builder()
                        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                        .ciphersuite(ciphersuite)
                        .build();

                    // 4. Alice creates the group.
                    let mut alice_group = MlsGroup::new(
                        &fixture.provider,
                        &alice_signer,
                        &group_config,
                        alice_credential,
                    )
                    .unwrap();

                    // 5. Alice adds Bob and the other members from the pool.
                    let mut members_to_add: Vec<KeyPackage> =
                        vec![bob_key_package.key_package().clone()];
                    members_to_add.extend(
                        fixture
                            .member_pool
                            .iter()
                            .take(size - 2)
                            .map(|kb| kb.key_package().clone()),
                    );

                    let (_, welcome, _) = alice_group
                        .add_members(&fixture.provider, &alice_signer, &members_to_add)
                        .unwrap();
                    alice_group.merge_pending_commit(&fixture.provider).unwrap();

                    // 6. Create a staged welcome for Bob.
                    let welcome_msg: MlsMessageIn = welcome.into();
                    let staged_welcome = StagedWelcome::new_from_welcome(
                        &fixture.provider,
                        group_config.join_config(),
                        welcome_msg.into_welcome().unwrap(),
                        Some(alice_group.export_ratchet_tree().into()),
                    )
                    .unwrap();
                    let bob_group = staged_welcome.into_group(&fixture.provider).unwrap();

                    // 7. Alice creates an application message to send to Bob.
                    // This is the message that Bob will receive.
                    let application_message = alice_group
                        .create_message(&fixture.provider, &alice_signer, b"Hello, Bob!")
                        .unwrap();

                    (bob_group, application_message)
                },
                |(mut bob_group, application_message)| {
                    // TIMED: The cost of decrypting and verifying the message.
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

// ─── Benchmark Runner ────────────────────────────────────────────────────────
fn run_all_benchmarks(c: &mut Criterion) {
    for &ciphersuite in CIPHERSUITES_TO_TEST {
        // This is the one-time setup call.
        let fixture = setup_fixture(ciphersuite);

        // ─── Objective 1 ─────────────────────────────────────────────
        benchmark_key_package_creation(c, &fixture);

        // ─── Objective 2 ─────────────────────────────────────────────
        benchmark_group_creation(c, &fixture);

        // ─── Objective 3 ─────────────────────────────────────────────
        benchmark_add_member_sender(c, &fixture);
        benchmark_add_member_receiver_new(c, &fixture);
        benchmark_add_member_receiver_existing(c, &fixture);

        // ─── Objective 4 ─────────────────────────────────────────────
        benchmark_self_update_sender(c, &fixture);
        benchmark_self_update_receiver(c, &fixture);

        // ─── Objective 5 ─────────────────────────────────────────────
        benchmark_remove_member_sender(c, &fixture);
        benchmark_remove_member_receiver(c, &fixture);

        // ─── Objective 6 ─────────────────────────────────────────────
        benchmark_send_application_message(c, &fixture);
        benchmark_receive_application_message(c, &fixture);
    }
}

// Register the benchmark group with Criterion.
criterion_group!(benches, run_all_benchmarks);
// Generate the main function to run the benchmarks.
criterion_main!(benches);
