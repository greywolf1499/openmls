//! # Benchmark Common Utilities
//!
//! This module provides a centralized set of common constants, configurations,
//! and utility functions for the OpenMLS benchmark suite. It is designed to
//! facilitate the setup and execution of benchmarks across various cryptographic
//! schemes and group sizes.
//!
//! The primary features of this module include:
//! - Pre-defined constants for different group sizes and ciphersuite categories.
//! - Environment variable parsing to allow for dynamic selection of benchmark
//!   parameters (e.g., `MLS_GROUP_SIZE_SET`, `MLS_CIPHERSUITE_GROUP`).
//! - Fixture setup functions (`setup_fixture`, `setup_key_package_fixture`) that
//!   prepare the necessary state for benchmarks, such as creating member pools
//!   and initializing cryptographic providers.
//! - Helper functions for creating members and classifying ciphersuites.

#![allow(dead_code)]

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_pqc_crypto::OpenMlsPqcProvider;
use openmls_traits::OpenMlsProvider;
use std::time::Instant;

// ─── Constants And Configuration ─────────────────────────────────────────────

/// A selection of standard group sizes for performance evaluation.
const STANDARD_GROUP_SIZES: &[usize] = &[2, 10, 50, 100, 200];
/// A selection of medium group sizes for performance evaluation.
const MEDIUM_GROUP_SIZES: &[usize] = &[300, 400];
/// A selection of semi-large group sizes for performance evaluation.
const SEMI_LARGE_GROUP_SIZES: &[usize] = &[500];
/// A selection of large group sizes for performance evaluation.
const LARGE_GROUP_SIZES: &[usize] = &[1000];

/// A comprehensive list of all ciphersuites targeted in the benchmarks.
/// This includes classic, NIST-standardized PQC, and other experimental suites.
pub const CIPHERSUITES_TO_TEST: &[Ciphersuite] = &[
    // Classic Default MLS Ciphersuites
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    // Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    // Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    // NIST Level 1 Ciphersuites
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F,
    // Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512,
    // NIST Level 3 Ciphersuites
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F,
    // Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S,
    // NIST Level 5 Ciphersuites
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F,
    // Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024,
];

/// Baseline ciphersuite using classical cryptography (Ed25519).
/// Used as a performance reference point.
const BASELINE_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];

/// Ciphersuites providing NIST Level 1 post-quantum security.
const NIST_L1_CIPHERSUITES: &[Ciphersuite] = &[
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA44,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_512,
];

/// Ciphersuites providing NIST Level 3 post-quantum security.
const NIST_L3_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA65];

/// Ciphersuites providing NIST Level 5 post-quantum security.
const NIST_L5_CIPHERSUITES: &[Ciphersuite] = &[
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_MLDSA87,
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_FALCON_1024,
];

/// SPHINCS+ ciphersuites (fast variant) for NIST Level 1.
const SPHINCS_L1_F_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F];

/// SPHINCS+ ciphersuites (fast variant) for NIST Level 3.
const SPHINCS_L3_F_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F];

/// SPHINCS+ ciphersuites (fast variant) for NIST Level 5.
const SPHINCS_L5_F_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F];

/// SPHINCS+ ciphersuites (small variant) for NIST Level 1.
const SPHINCS_L1_S_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S];

/// SPHINCS+ ciphersuites (small variant) for NIST Level 3.
const SPHINCS_L3_S_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S];

/// SPHINCS+ ciphersuites (small variant) for NIST Level 5.
const SPHINCS_L5_S_CIPHERSUITES: &[Ciphersuite] =
    &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S];

/// The maximum group size for which member pools are pre-generated.
pub const MAX_GROUP_SIZE: usize = 1000;

// ─── Benchmark Fixtures And Setup ────────────────────────────────────────────

/// A comprehensive fixture for benchmarks requiring a pre-existing group state.
///
/// This struct holds all necessary components for complex benchmarks, such as
/// adding members to a group. It includes a crypto provider, the target ciphersuite,
/// a pre-generated key package for a new member, and a pool of existing members
/// to construct groups of various sizes. This setup minimizes per-benchmark overhead.
pub struct BenchmarkFixture {
    pub provider: OpenMlsPqcProvider,
    pub ciphersuite: Ciphersuite,
    pub new_member_kp_bundle: KeyPackageBundle,
    pub member_pool: Vec<KeyPackageBundle>,
}

/// A lightweight fixture for benchmarks focused on key package generation.
///
/// This struct provides the minimal necessary components (provider and ciphersuite)
/// for benchmarks that do not require a pre-existing group state, such as measuring
/// the time to create a key package.
pub struct KeyPackageBenchFixture {
    pub provider: OpenMlsPqcProvider,
    pub ciphersuite: Ciphersuite,
}

/// Creates a new member, generating their credential, signature keys, and key package.
///
/// This helper function encapsulates the logic for generating all artifacts
/// required for a new participant to join a group.
pub fn create_member(
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

/// Sets up the `BenchmarkFixture` for a given ciphersuite.
///
/// This function performs the one-time, potentially expensive setup required for
/// a suite of benchmarks. It initializes the PQC crypto provider and pre-generates
/// a large pool of member key packages. This ensures that the benchmark measurements
/// are not skewed by setup costs.
pub fn setup_fixture(ciphersuite: Ciphersuite) -> BenchmarkFixture {
    println!(
        "\nSetting up ONE-TIME fixture for ciphersuite: {:?}",
        ciphersuite
    );
    let start = Instant::now();

    let provider = OpenMlsPqcProvider::default();

    let (_, _, new_member_kp_bundle) = create_member(ciphersuite, &provider, b"new_member");

    let group_sizes = get_group_sizes();
    let max_size = group_sizes.iter().max().cloned().unwrap_or(MAX_GROUP_SIZE);

    println!(
        "Generating member pool of size {}... (This may take a moment)",
        max_size
    );

    let member_pool: Vec<KeyPackageBundle> = (0..max_size)
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

/// Sets up the `KeyPackageBenchFixture` for a given ciphersuite.
///
/// This function provides a minimal, lightweight setup for benchmarks that
/// only require a crypto provider and a ciphersuite specification.
pub fn setup_key_package_fixture(ciphersuite: Ciphersuite) -> KeyPackageBenchFixture {
    println!(
        "\nSetting up LIGHTWEIGHT fixture for ciphersuite: {:?}",
        ciphersuite
    );
    let start = Instant::now();

    let provider = OpenMlsPqcProvider::default();

    println!(
        "Lightweight fixture setup complete in {:.2?}.\n",
        start.elapsed()
    );

    KeyPackageBenchFixture {
        provider,
        ciphersuite,
    }
}

/// Determines the set of group sizes to use for benchmarks based on an environment variable.
///
/// Reads the `MLS_GROUP_SIZE_SET` environment variable to select a predefined
/// set of group sizes. This allows for flexible benchmark execution, from quick
/// checks with small groups to comprehensive runs across all sizes.
///
/// Available sets: "standard", "medium", "semi_large", "large", "all".
/// Defaults to "standard" if the variable is not set or invalid.
pub fn get_group_sizes() -> Vec<usize> {
    match std::env::var("MLS_GROUP_SIZE_SET") {
        Ok(set) => {
            println!("Targeting group size set: {}", set);
            match set.to_lowercase().as_str() {
                "standard" => STANDARD_GROUP_SIZES.to_vec(),
                "medium" => MEDIUM_GROUP_SIZES.to_vec(),
                "semi_large" => SEMI_LARGE_GROUP_SIZES.to_vec(),
                "large" => LARGE_GROUP_SIZES.to_vec(),
                "all" => all_group_sizes(),
                _ => {
                    eprintln!(
                        "Warning: Unknown group size set '{}'. Defaulting to standard.",
                        set
                    );
                    STANDARD_GROUP_SIZES.to_vec()
                }
            }
        }
        Err(_) => {
            // Default to standard sizes if the environment variable is not set.
            STANDARD_GROUP_SIZES.to_vec()
        }
    }
}

/// Determines the set of ciphersuites to test based on an environment variable.
///
/// Reads the `MLS_CIPHERSUITE_GROUP` environment variable to select a predefined
/// group of ciphersuites. This enables targeted performance analysis of specific
/// cryptographic algorithms or security levels.
///
/// Available groups: "baseline", "nist1", "nist3", "nist5", "sphincs_l1_f", etc.
/// Defaults to all ciphersuites if the variable is not set or invalid.
pub fn get_ciphersuites_to_test() -> Vec<Ciphersuite> {
    match std::env::var("MLS_CIPHERSUITE_GROUP") {
        Ok(group) => {
            println!("Targeting ciphersuite group: {}", group);
            match group.to_lowercase().as_str() {
                "baseline" => BASELINE_CIPHERSUITES.to_vec(),
                "nist1" => NIST_L1_CIPHERSUITES.to_vec(),
                "nist3" => NIST_L3_CIPHERSUITES.to_vec(),
                "nist5" => NIST_L5_CIPHERSUITES.to_vec(),
                "sphincs_l1_f" => SPHINCS_L1_F_CIPHERSUITES.to_vec(),
                "sphincs_l3_f" => SPHINCS_L3_F_CIPHERSUITES.to_vec(),
                "sphincs_l5_f" => SPHINCS_L5_F_CIPHERSUITES.to_vec(),
                "sphincs_l1_s" => SPHINCS_L1_S_CIPHERSUITES.to_vec(),
                "sphincs_l3_s" => SPHINCS_L3_S_CIPHERSUITES.to_vec(),
                "sphincs_l5_s" => SPHINCS_L5_S_CIPHERSUITES.to_vec(),
                _ => {
                    eprintln!(
                        "Warning: Unknown ciphersuite group '{}'. Defaulting to all.",
                        group
                    );
                    all_ciphersuites()
                }
            }
        }
        Err(_) => {
            // If the environment variable is not set, run all ciphersuites.
            println!("No ciphersuite group specified. Running all ciphersuites.");
            all_ciphersuites()
        }
    }
}

/// Checks if a given ciphersuite uses a SPHINCS+ signature scheme.
pub fn is_sphincs_ciphersuite(ciphersuite: Ciphersuite) -> bool {
    matches!(
        ciphersuite,
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256F
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_128S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_192S
            | Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_SPHINCS_SHA_256S
    )
}

/// Returns a concatenated vector of all defined ciphersuite groups.
fn all_ciphersuites() -> Vec<Ciphersuite> {
    [
        BASELINE_CIPHERSUITES,
        NIST_L1_CIPHERSUITES,
        NIST_L3_CIPHERSUITES,
        NIST_L5_CIPHERSUITES,
        SPHINCS_L1_F_CIPHERSUITES,
        SPHINCS_L3_F_CIPHERSUITES,
        SPHINCS_L5_F_CIPHERSUITES,
        SPHINCS_L1_S_CIPHERSUITES,
        SPHINCS_L3_S_CIPHERSUITES,
        SPHINCS_L5_S_CIPHERSUITES,
    ]
    .concat()
}

/// Returns a concatenated vector of all defined group size categories.
fn all_group_sizes() -> Vec<usize> {
    [
        STANDARD_GROUP_SIZES,
        MEDIUM_GROUP_SIZES,
        SEMI_LARGE_GROUP_SIZES,
        LARGE_GROUP_SIZES,
    ]
    .concat()
}
