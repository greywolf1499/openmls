#!/usr/bin/env zsh

# ==============================================================================
# # Granular Benchmark Execution Script
#
# This script provides a systematic and automated framework for executing the
# OpenMLS benchmark suite. It is designed to facilitate comprehensive performance
# analysis by systematically iterating through various configurations of group
# sizes and cryptographic ciphersuites.
#
# The execution is structured into a multi-phase process, controlled by
# environment variables (`MLS_GROUP_SIZE_SET` and `MLS_CIPHERSUITE_GROUP`) that
# are interpreted by the individual Rust benchmark files. This design allows for
# a highly granular and reproducible testing methodology, while maintaining a
# balance between time and space complexity of running the benchmarks.
#
# ## Execution Logic:
# The script employs three nested loops:
# 1. **Outer Loop (Group Size Sets):** Iterates through predefined sets of group
#    sizes (e.g., "standard", "large"). This allows for separating potentially
#    time-consuming benchmarks for very large groups from more standard runs.
# 2. **Middle Loop (Ciphersuite Groups):** Iterates through logical groupings of
#    ciphersuites (e.g., "baseline", "nist1", "sphincs_l1_f"). This enables
#    targeted analysis of specific cryptographic algorithm families.
# 3. **Inner Loop (Benchmark Targets):** Executes each individual benchmark file
#    (e.g., `1_key_package`, `2_group_creation`) using `cargo bench`.
#
# The script ensures that each benchmark is run with a specific, controlled
# configuration, with clear logging to track progress and a final summary of
# the total execution time.
# ==============================================================================

# --- Configuration ---
# -e: Exit immediately if a command exits with a non-zero status.
# -u: Treat unset variables as an error when substituting.
# -o pipefail: The return value of a pipeline is the status of the last
#              command to exit with a non-zero status, or zero if no
#              command exited with a non-zero status.
set -e; set -u; set -o pipefail

# --- Color Codes for Output Formatting ---
# Use tput to generate terminal control codes for colored output if available,
# otherwise fall back to standard ANSI escape codes.
if command -v tput >/dev/null 2>&1; then
    GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4); RED=$(tput setaf 1); NC=$(tput sgr0)
else
    GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
fi

# --- Main Script Logic ---
main() {
    echo "${BLUE}==============================================${NC}"
    echo "${BLUE}  Starting Multi-Phase Granular Benchmark Suite ${NC}"
    echo "${BLUE}==============================================${NC}"
    echo

    # Ensure the script is run from the project's root directory.
    if [[ ! -f "Cargo.toml" ]]; then
        echo "${RED}Error: Cargo.toml not found.${NC}\nPlease run from project root.${NC}"
        exit 1
    fi

    # --- Define the benchmark execution plan ---

    # An array defining the sets of group sizes to be tested in sequence.
    # These correspond to the `MLS_GROUP_SIZE_SET` environment variable.
    local -a size_sets=(
        "standard"
        "medium"
        "semi_large"
        "large"
    )

    # An array of all individual benchmark targets to be executed.
    # These correspond to the `--bench` argument for `cargo bench`.
    local -a bench_targets=(
        "1_key_package"
        "2_group_creation"
        "3_1_add_member_sender"
        "3_2_add_member_receiver_new"
        "3_3_add_member_receiver_existing"
        "4_1_self_update_sender"
        "4_2_self_update_receiver"
        "5_1_remove_member_sender"
        "5_2_remove_member_receiver"
        "6_1_messaging_sender"
        "6_2_messaging_receiver"
    )

    # An array defining the groups of ciphersuites to be tested.
    # These correspond to the `MLS_CIPHERSUITE_GROUP` environment variable.
    local -a ciphersuite_groups=(
        "baseline"
        "nist1"
        "nist3"
        "nist5"
        "sphincs_l1_f"
        "sphincs_l3_f"
        "sphincs_l5_f"
        "sphincs_l1_s"
        "sphincs_l3_s"
        "sphincs_l5_s"
    )

    # Initialize progress tracking and timing variables.
    local start_time=$SECONDS
    local total_runs=$(( ${#size_sets[@]} * ${#ciphersuite_groups[@]} * ${#bench_targets[@]} ))
    local current_run=1

    # --- Outermost loop: Iterate through group size sets ---
    for size_set in "${size_sets[@]}"; do
        echo "${BLUE}======================================================${NC}"
        # Use Zsh native syntax ${(U)variable} for uppercase conversion.
        echo "${BLUE}  PHASE START: BENCHMARKING FOR GROUP SIZE SET: ${(U)size_set}  ${NC}"
        echo "${BLUE}======================================================${NC}"
        export MLS_GROUP_SIZE_SET="$size_set"

        # --- Middle loop: Iterate through ciphersuite groups ---
        for group_name in "${ciphersuite_groups[@]}"; do
            echo "${YELLOW}===== Starting Ciphersuite Group: $group_name =====${NC}"
            export MLS_CIPHERSUITE_GROUP="$group_name"

            # --- Inner loop: Iterate through each benchmark file ---
            for bench_name in "${bench_targets[@]}"; do
                # Optimization: The '1_key_package' benchmark does not depend on group size.
                # Therefore, it is only run once during the first ("standard") phase to avoid redundancy.
                if [[ "$size_set" != "standard" && "$bench_name" == "1_key_package" ]]; then
                    ((current_run++))
                    continue
                fi

                # Verify that the benchmark file exists before attempting to run it.
                if [[ ! -f "benches/${bench_name}.rs" ]]; then
                    echo "${RED}►►► Skipping: Target '${bench_name}' not found.${NC}"
                    ((current_run++))
                    continue
                fi

                echo
                echo "►►► Running (${current_run}/${total_runs}): Set '${size_set}', Group '${group_name}', Target '${bench_name}'"
                echo "------------------------------------------------------------------"
                # Execute the specific benchmark using cargo.
                cargo bench --bench "$bench_name"
                echo "------------------------------------------------------------------"
                echo "${GREEN}▲▲▲ Finished: Set '${size_set}', Group '${group_name}', Target '${bench_name}'${NC}"
                ((current_run++))
            done

            # Unset the variable to ensure a clean state for the next iteration.
            unset MLS_CIPHERSUITE_GROUP
            echo
            echo "${YELLOW}===== Completed All Benchmarks for Group: $group_name =====${NC}"
            echo
        done
        # Unset the variable to ensure a clean state for the next phase.
        unset MLS_GROUP_SIZE_SET
    done

    # --- Final Summary ---
    local end_time=$SECONDS
    local duration=$((end_time - start_time))

    echo "${BLUE}==============================================${NC}"
    echo "${GREEN} ✔ All benchmark phases completed successfully! ${NC}"
    echo "${BLUE}==============================================${NC}"
    printf "Total execution time: %d minutes and %d seconds\n" $((duration / 60)) $((duration % 60))
    echo
}

# Execute the main function, passing along any command-line arguments.
main "$@"
