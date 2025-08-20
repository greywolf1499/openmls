# OpenMLS PQC Experiment Benchmark Suite

This directory contains the benchmark suite for the OpenMLS Post-Quantum Cryptography (PQC) experiment, built using the [Criterion.rs](https://github.com/bheisler/criterion.rs) framework. The primary goal of this suite is to systematically measure and analyze the performance of core Messaging Layer Security (MLS) operations when integrated with various classical and post-quantum cryptographic algorithms.

## Structure

The benchmark suite is organized into several files, each targeting a specific MLS operation. A common module provides shared utilities and test fixtures.

-   `common.rs`: A foundational module that contains shared logic, including:
    -   Definitions of ciphersuite groups (e.g., `BASELINE_CIPHERSUITES`, `NIST_L1_CIPHERSUITES`).
    -   Definitions of group size sets (e.g., `STANDARD_GROUP_SIZES`, `LARGE_GROUP_SIZES`).
    -   Fixture setup functions (`setup_fixture`, `setup_key_package_fixture`) to prepare the necessary state for benchmarks, such as pre-generating pools of members.
    -   Helper functions to parse environment variables (`MLS_GROUP_SIZE_SET`, `MLS_CIPHERSUITE_GROUP`) that control which tests are run.

### Benchmark Targets

Each numbered file corresponds to a specific operation being measured:

1.  **`1_key_package.rs`**: Measures the time to create a `KeyPackage`, which is the first step for a client to join a group.
2.  **`2_group_creation.rs`**: Measures the time to create a new group and add an initial set of members.
3.  **Member Addition**:
    -   `3_1_add_member_sender.rs`: Measures the cost for an existing member to create a `Commit` that adds a new member.
    -   `3_2_add_member_receiver_new.rs`: Measures the cost for a new member to process a `Welcome` message and join the group.
    -   `3_3_add_member_receiver_existing.rs`: Measures the cost for an existing member to process a `Commit` that adds another member.
4.  **Self-Update (Key Rotation)**:
    -   `4_1_self_update_sender.rs`: Measures the cost for a member to create a `Commit` to update their own key material.
    -   `4_2_self_update_receiver.rs`: Measures the cost for an existing member to process another member's self-update `Commit`.
5.  **Member Removal**:
    -   `5_1_remove_member_sender.rs`: Measures the cost for a member to create a `Commit` that removes another member from the group.
    -   `5_2_remove_member_receiver.rs`: Measures the cost for an existing member to process a `Commit` that removes another member.
6.  **Application Messaging**:
    -   `6_1_messaging_sender.rs`: Measures the cost to encrypt and send an application message to the group.
    -   `6_2_messaging_receiver.rs`: Measures the cost to receive and decrypt an application message from the group.

## How to Run the Benchmarks

The benchmarks are designed to be run via the `run_benchmarks_by_ciphersuite.zsh` script located in the project root, which provides a controlled, granular execution flow.

### Automated Execution (Recommended)

The `run_benchmarks_by_ciphersuite.zsh` script automates the entire process, iterating through all defined ciphersuite groups and group size sets.

To run the full suite, execute the script from the project's root directory:

```sh
./run_benchmarks_by_ciphersuite.zsh
```

The script sets the following environment variables to control the benchmarks:

-   `MLS_GROUP_SIZE_SET`: Determines the group sizes to be tested.
    -   `standard`: [2, 10, 50, 100, 200]
    -   `medium`: [300, 400]
    -   `semi_large`: [500]
    -   `large`: [1000]
-   `MLS_CIPHERSUITE_GROUP`: Determines the set of ciphersuites to be tested.
    -   `baseline`: Classical Ed25519
    -   `nist1`, `nist3`, `nist5`: NIST PQC security levels 1, 3, and 5 for lattice-based schemes (ML-DSA, Falcon).
    -   `sphincs_l1_f`, `sphincs_l3_f`, `sphincs_l5_f`: SPHINCS+ Fast variants for levels 1, 3, 5.
    -   `sphincs_l1_s`, `sphincs_l3_s`, `sphincs_l5_s`: SPHINCS+ Small variants for levels 1, 3, 5.

### Manual Execution

You can also run individual benchmark targets manually using `cargo bench`. This is useful for quick, targeted tests.

1.  **Set Environment Variables (Optional)**: If you want to test a specific configuration, export the variables first. If they are not set, the benchmarks will default to a standard set of parameters.

    ```sh
    export MLS_GROUP_SIZE_SET="standard"
    export MLS_CIPHERSUITE_GROUP="nist1"
    ```

2.  **Run the Benchmark**: Use the `--bench` flag to specify the target file (without the `.rs` extension).

    ```sh
    # Example: Run only the group creation benchmark
    cargo bench --bench 2_group_creation
    ```

## Output

Criterion.rs will generate detailed reports for each benchmark in the `target/criterion` directory. These reports include HTML summaries with graphs, statistical analysis, and performance measurements that can be used for analysis.
