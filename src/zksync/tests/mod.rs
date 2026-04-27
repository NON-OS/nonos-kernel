// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod bridge;
mod config;
mod constants;
mod eravm;
mod error;
mod prover;
mod sequencer;
mod state;
mod types;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("zksync");

    // Bridge tests (22)
    suite.add(TestCase::new("deposit_handler_new", bridge::test_deposit_handler_new));
    suite.add(TestCase::new("deposit_handler_default", bridge::test_deposit_handler_default));
    suite.add(TestCase::new("deposit_handler_queue", bridge::test_deposit_handler_queue));
    suite.add(TestCase::new(
        "deposit_handler_queue_multiple",
        bridge::test_deposit_handler_queue_multiple,
    ));
    suite.add(TestCase::new(
        "deposit_handler_process_next_empty",
        bridge::test_deposit_handler_process_next_empty,
    ));
    suite.add(TestCase::new(
        "deposit_handler_process_next",
        bridge::test_deposit_handler_process_next,
    ));
    suite.add(TestCase::new(
        "deposit_handler_process_next_fifo",
        bridge::test_deposit_handler_process_next_fifo,
    ));
    suite.add(TestCase::new(
        "deposit_handler_process_accumulates_balance",
        bridge::test_deposit_handler_process_accumulates_balance,
    ));
    suite.add(TestCase::new("deposit_clone", bridge::test_deposit_clone));
    suite.add(TestCase::new("deposit_debug", bridge::test_deposit_debug));
    suite.add(TestCase::new("withdraw_handler_new", bridge::test_withdraw_handler_new));
    suite.add(TestCase::new("withdraw_handler_default", bridge::test_withdraw_handler_default));
    suite.add(TestCase::new("withdraw_handler_initiate", bridge::test_withdraw_handler_initiate));
    suite.add(TestCase::new(
        "withdraw_handler_initiate_insufficient_balance",
        bridge::test_withdraw_handler_initiate_insufficient_balance,
    ));
    suite.add(TestCase::new(
        "withdraw_handler_initiate_returns_hash",
        bridge::test_withdraw_handler_initiate_returns_hash,
    ));
    suite.add(TestCase::new(
        "withdraw_handler_initiate_multiple",
        bridge::test_withdraw_handler_initiate_multiple,
    ));
    suite.add(TestCase::new(
        "withdraw_handler_finalize_batch",
        bridge::test_withdraw_handler_finalize_batch,
    ));
    suite.add(TestCase::new(
        "withdraw_handler_finalize_batch_partial",
        bridge::test_withdraw_handler_finalize_batch_partial,
    ));
    suite.add(TestCase::new(
        "withdraw_handler_finalize_batch_none",
        bridge::test_withdraw_handler_finalize_batch_none,
    ));
    suite.add(TestCase::new(
        "withdraw_handler_different_hashes",
        bridge::test_withdraw_handler_different_hashes,
    ));

    // Config tests (19)
    suite.add(TestCase::new(
        "config_default_max_tx_per_block",
        config::test_config_default_max_tx_per_block,
    ));
    suite.add(TestCase::new(
        "config_default_max_blocks_per_batch",
        config::test_config_default_max_blocks_per_batch,
    ));
    suite.add(TestCase::new(
        "config_default_block_time_ms",
        config::test_config_default_block_time_ms,
    ));
    suite.add(TestCase::new(
        "config_default_gas_per_pubdata_byte",
        config::test_config_default_gas_per_pubdata_byte,
    ));
    suite.add(TestCase::new(
        "config_default_max_gas_per_batch",
        config::test_config_default_max_gas_per_batch,
    ));
    suite.add(TestCase::new("config_default_l1_chain_id", config::test_config_default_l1_chain_id));
    suite.add(TestCase::new("config_default_l2_chain_id", config::test_config_default_l2_chain_id));
    suite.add(TestCase::new(
        "config_default_sequencer_address",
        config::test_config_default_sequencer_address,
    ));
    suite.add(TestCase::new(
        "config_default_bootloader_hash",
        config::test_config_default_bootloader_hash,
    ));
    suite.add(TestCase::new(
        "config_default_default_aa_hash",
        config::test_config_default_default_aa_hash,
    ));
    suite.add(TestCase::new("config_mainnet_l1_chain_id", config::test_config_mainnet_l1_chain_id));
    suite.add(TestCase::new("config_mainnet_l2_chain_id", config::test_config_mainnet_l2_chain_id));
    suite.add(TestCase::new("config_sepolia_l1_chain_id", config::test_config_sepolia_l1_chain_id));
    suite.add(TestCase::new("config_sepolia_l2_chain_id", config::test_config_sepolia_l2_chain_id));
    suite.add(TestCase::new("config_clone", config::test_config_clone));
    suite.add(TestCase::new("config_debug_format", config::test_config_debug_format));
    suite.add(TestCase::new("config_custom_values", config::test_config_custom_values));
    suite.add(TestCase::new(
        "config_mainnet_inherits_defaults",
        config::test_config_mainnet_inherits_defaults,
    ));
    suite.add(TestCase::new(
        "config_sepolia_inherits_defaults",
        config::test_config_sepolia_inherits_defaults,
    ));

    // Constants tests (26)
    suite.add(TestCase::new("syscall_submit_tx", constants::test_syscall_submit_tx));
    suite.add(TestCase::new("syscall_get_tx_status", constants::test_syscall_get_tx_status));
    suite.add(TestCase::new("syscall_get_balance", constants::test_syscall_get_balance));
    suite.add(TestCase::new("syscall_get_nonce", constants::test_syscall_get_nonce));
    suite.add(TestCase::new("syscall_call", constants::test_syscall_call));
    suite.add(TestCase::new("syscall_estimate_gas", constants::test_syscall_estimate_gas));
    suite.add(TestCase::new("syscall_get_block", constants::test_syscall_get_block));
    suite.add(TestCase::new("syscall_get_batch", constants::test_syscall_get_batch));
    suite.add(TestCase::new("syscall_prove_batch", constants::test_syscall_prove_batch));
    suite.add(TestCase::new("syscall_get_proof", constants::test_syscall_get_proof));
    suite.add(TestCase::new("syscall_bridge_deposit", constants::test_syscall_bridge_deposit));
    suite.add(TestCase::new("syscall_bridge_withdraw", constants::test_syscall_bridge_withdraw));
    suite.add(TestCase::new(
        "syscall_numbers_sequential",
        constants::test_syscall_numbers_sequential,
    ));
    suite.add(TestCase::new("syscall_numbers_unique", constants::test_syscall_numbers_unique));
    suite.add(TestCase::new("public_exports_address", constants::test_public_exports_address));
    suite.add(TestCase::new("public_exports_u256", constants::test_public_exports_u256));
    suite.add(TestCase::new(
        "public_exports_batch_number",
        constants::test_public_exports_batch_number,
    ));
    suite.add(TestCase::new(
        "public_exports_block_number",
        constants::test_public_exports_block_number,
    ));
    suite.add(TestCase::new("public_exports_nonce", constants::test_public_exports_nonce));
    suite.add(TestCase::new("public_exports_gas", constants::test_public_exports_gas));
    suite.add(TestCase::new("public_exports_tx_hash", constants::test_public_exports_tx_hash));
    suite.add(TestCase::new(
        "public_exports_zksync_config",
        constants::test_public_exports_zksync_config,
    ));
    suite.add(TestCase::new(
        "public_exports_zksync_error",
        constants::test_public_exports_zksync_error,
    ));
    suite.add(TestCase::new(
        "public_exports_goldilocks_field",
        constants::test_public_exports_goldilocks_field,
    ));
    suite.add(TestCase::new(
        "public_exports_sparse_merkle_tree",
        constants::test_public_exports_sparse_merkle_tree,
    ));
    suite.add(TestCase::new(
        "init_zksync_function_exists",
        constants::test_init_zksync_function_exists,
    ));
    suite.add(TestCase::new(
        "is_initialized_function_exists",
        constants::test_is_initialized_function_exists,
    ));

    // EraVM tests (30)
    suite.add(TestCase::new("vm_memory_new", eravm::test_vm_memory_new));
    suite.add(TestCase::new("vm_memory_default", eravm::test_vm_memory_default));
    suite.add(TestCase::new("vm_memory_with_capacity", eravm::test_vm_memory_with_capacity));
    suite.add(TestCase::new("vm_memory_store_load", eravm::test_vm_memory_store_load));
    suite.add(TestCase::new("vm_memory_store_expands", eravm::test_vm_memory_store_expands));
    suite.add(TestCase::new("vm_memory_load_expands", eravm::test_vm_memory_load_expands));
    suite.add(TestCase::new("vm_memory_store_at_offset", eravm::test_vm_memory_store_at_offset));
    suite.add(TestCase::new("vm_memory_load_u256", eravm::test_vm_memory_load_u256));
    suite.add(TestCase::new("vm_memory_store_u256", eravm::test_vm_memory_store_u256));
    suite.add(TestCase::new("vm_memory_load_u256_zeros", eravm::test_vm_memory_load_u256_zeros));
    suite.add(TestCase::new("vm_memory_clear", eravm::test_vm_memory_clear));
    suite.add(TestCase::new("vm_memory_page_alignment", eravm::test_vm_memory_page_alignment));
    suite.add(TestCase::new("vm_memory_multiple_stores", eravm::test_vm_memory_multiple_stores));
    suite.add(TestCase::new("vm_memory_overwrite", eravm::test_vm_memory_overwrite));
    suite.add(TestCase::new("execution_context_new", eravm::test_execution_context_new));
    suite.add(TestCase::new(
        "execution_context_initial_state",
        eravm::test_execution_context_initial_state,
    ));
    suite.add(TestCase::new(
        "execution_context_consume_gas",
        eravm::test_execution_context_consume_gas,
    ));
    suite.add(TestCase::new(
        "execution_context_consume_gas_exceeds_limit",
        eravm::test_execution_context_consume_gas_exceeds_limit,
    ));
    suite.add(TestCase::new(
        "execution_context_consume_gas_exact_limit",
        eravm::test_execution_context_consume_gas_exact_limit,
    ));
    suite.add(TestCase::new(
        "execution_context_remaining_gas",
        eravm::test_execution_context_remaining_gas,
    ));
    suite.add(TestCase::new("execution_context_revert", eravm::test_execution_context_revert));
    suite.add(TestCase::new("execution_context_finish", eravm::test_execution_context_finish));
    suite.add(TestCase::new(
        "execution_context_is_finished_false",
        eravm::test_execution_context_is_finished_false,
    ));
    suite.add(TestCase::new(
        "execution_context_is_finished_after_finish",
        eravm::test_execution_context_is_finished_after_finish,
    ));
    suite.add(TestCase::new(
        "execution_context_is_finished_after_revert",
        eravm::test_execution_context_is_finished_after_revert,
    ));
    suite.add(TestCase::new(
        "execution_context_memory_access",
        eravm::test_execution_context_memory_access,
    ));
    suite.add(TestCase::new(
        "execution_context_multiple_gas_consumption",
        eravm::test_execution_context_multiple_gas_consumption,
    ));
    suite.add(TestCase::new(
        "execution_context_gas_consumption_fails_mid_execution",
        eravm::test_execution_context_gas_consumption_fails_mid_execution,
    ));

    // Error tests (24)
    suite.add(TestCase::new("error_not_initialized", error::test_error_not_initialized));
    suite.add(TestCase::new("error_invalid_transaction", error::test_error_invalid_transaction));
    suite.add(TestCase::new("error_invalid_signature", error::test_error_invalid_signature));
    suite.add(TestCase::new("error_insufficient_balance", error::test_error_insufficient_balance));
    suite.add(TestCase::new("error_nonce_mismatch", error::test_error_nonce_mismatch));
    suite.add(TestCase::new("error_gas_limit_exceeded", error::test_error_gas_limit_exceeded));
    suite.add(TestCase::new("error_invalid_proof", error::test_error_invalid_proof));
    suite.add(TestCase::new("error_batch_not_found", error::test_error_batch_not_found));
    suite.add(TestCase::new("error_block_not_found", error::test_error_block_not_found));
    suite.add(TestCase::new("error_account_not_found", error::test_error_account_not_found));
    suite.add(TestCase::new("error_storage_error", error::test_error_storage_error));
    suite.add(TestCase::new("error_proving_failed", error::test_error_proving_failed));
    suite.add(TestCase::new(
        "error_witness_generation_failed",
        error::test_error_witness_generation_failed,
    ));
    suite.add(TestCase::new(
        "error_l1_communication_failed",
        error::test_error_l1_communication_failed,
    ));
    suite.add(TestCase::new("error_bridge_error", error::test_error_bridge_error));
    suite.add(TestCase::new("error_capability_denied", error::test_error_capability_denied));
    suite.add(TestCase::new("error_invalid_input", error::test_error_invalid_input));
    suite.add(TestCase::new("error_out_of_memory", error::test_error_out_of_memory));
    suite.add(TestCase::new("error_internal_error", error::test_error_internal_error));
    suite.add(TestCase::new("error_debug_format", error::test_error_debug_format));
    suite.add(TestCase::new("error_equality", error::test_error_equality));
    suite.add(TestCase::new("error_clone", error::test_error_clone));
    suite.add(TestCase::new("error_copy", error::test_error_copy));
    suite
        .add(TestCase::new("all_error_variants_distinct", error::test_all_error_variants_distinct));

    // Prover tests (3)
    suite.add(TestCase::new("prover_module_exists", prover::test_module_exists));
    suite.add(TestCase::new("prover_basic_constants", prover::test_basic_constants));
    suite.add(TestCase::new("prover_basic_operations", prover::test_basic_operations));

    // Sequencer tests (30)
    suite.add(TestCase::new("transaction_pool_new", sequencer::test_transaction_pool_new));
    suite.add(TestCase::new("transaction_pool_default", sequencer::test_transaction_pool_default));
    suite.add(TestCase::new("transaction_pool_insert", sequencer::test_transaction_pool_insert));
    suite.add(TestCase::new(
        "transaction_pool_insert_duplicate",
        sequencer::test_transaction_pool_insert_duplicate,
    ));
    suite.add(TestCase::new(
        "transaction_pool_insert_full",
        sequencer::test_transaction_pool_insert_full,
    ));
    suite.add(TestCase::new("transaction_pool_get", sequencer::test_transaction_pool_get));
    suite.add(TestCase::new(
        "transaction_pool_get_nonexistent",
        sequencer::test_transaction_pool_get_nonexistent,
    ));
    suite
        .add(TestCase::new("transaction_pool_contains", sequencer::test_transaction_pool_contains));
    suite.add(TestCase::new("transaction_pool_remove", sequencer::test_transaction_pool_remove));
    suite.add(TestCase::new(
        "transaction_pool_remove_nonexistent",
        sequencer::test_transaction_pool_remove_nonexistent,
    ));
    suite.add(TestCase::new(
        "transaction_pool_get_pending_for",
        sequencer::test_transaction_pool_get_pending_for,
    ));
    suite.add(TestCase::new(
        "transaction_pool_get_pending_for_empty",
        sequencer::test_transaction_pool_get_pending_for_empty,
    ));
    suite.add(TestCase::new(
        "transaction_pool_next_nonce_for",
        sequencer::test_transaction_pool_next_nonce_for,
    ));
    suite.add(TestCase::new(
        "transaction_pool_next_nonce_for_current_higher",
        sequencer::test_transaction_pool_next_nonce_for_current_higher,
    ));
    suite.add(TestCase::new(
        "transaction_pool_drain_batch",
        sequencer::test_transaction_pool_drain_batch,
    ));
    suite.add(TestCase::new(
        "transaction_pool_drain_batch_more_than_available",
        sequencer::test_transaction_pool_drain_batch_more_than_available,
    ));
    suite.add(TestCase::new("transaction_executor_new", sequencer::test_transaction_executor_new));
    suite.add(TestCase::new(
        "transaction_executor_current_block",
        sequencer::test_transaction_executor_current_block,
    ));
    suite.add(TestCase::new(
        "transaction_executor_execute_success",
        sequencer::test_transaction_executor_execute_success,
    ));
    suite.add(TestCase::new(
        "transaction_executor_execute_nonce_too_low",
        sequencer::test_transaction_executor_execute_nonce_too_low,
    ));
    suite.add(TestCase::new(
        "transaction_executor_execute_nonce_too_high",
        sequencer::test_transaction_executor_execute_nonce_too_high,
    ));
    suite.add(TestCase::new(
        "transaction_executor_execute_insufficient_balance",
        sequencer::test_transaction_executor_execute_insufficient_balance,
    ));
    suite.add(TestCase::new(
        "transaction_executor_validate_success",
        sequencer::test_transaction_executor_validate_success,
    ));
    suite.add(TestCase::new(
        "transaction_executor_validate_nonce_too_low",
        sequencer::test_transaction_executor_validate_nonce_too_low,
    ));
    suite.add(TestCase::new(
        "transaction_executor_validate_insufficient_balance",
        sequencer::test_transaction_executor_validate_insufficient_balance,
    ));
    suite.add(TestCase::new(
        "transaction_executor_increments_nonce",
        sequencer::test_transaction_executor_increments_nonce,
    ));
    suite.add(TestCase::new(
        "transaction_executor_transfers_value",
        sequencer::test_transaction_executor_transfers_value,
    ));

    // State tests (47)
    suite.add(TestCase::new("sparse_merkle_tree_new", state::test_sparse_merkle_tree_new));
    suite.add(TestCase::new("sparse_merkle_tree_default", state::test_sparse_merkle_tree_default));
    suite.add(TestCase::new("sparse_merkle_tree_insert", state::test_sparse_merkle_tree_insert));
    suite.add(TestCase::new(
        "sparse_merkle_tree_get_nonexistent",
        state::test_sparse_merkle_tree_get_nonexistent,
    ));
    suite.add(TestCase::new("sparse_merkle_tree_remove", state::test_sparse_merkle_tree_remove));
    suite.add(TestCase::new(
        "sparse_merkle_tree_remove_nonexistent",
        state::test_sparse_merkle_tree_remove_nonexistent,
    ));
    suite.add(TestCase::new(
        "sparse_merkle_tree_root_changes_on_insert",
        state::test_sparse_merkle_tree_root_changes_on_insert,
    ));
    suite.add(TestCase::new(
        "sparse_merkle_tree_root_changes_on_remove",
        state::test_sparse_merkle_tree_root_changes_on_remove,
    ));
    suite.add(TestCase::new("sparse_merkle_tree_proof", state::test_sparse_merkle_tree_proof));
    suite.add(TestCase::new(
        "sparse_merkle_tree_proof_nonexistent",
        state::test_sparse_merkle_tree_proof_nonexistent,
    ));
    suite.add(TestCase::new("merkle_proof_verify", state::test_merkle_proof_verify));
    suite.add(TestCase::new(
        "merkle_proof_verify_wrong_root",
        state::test_merkle_proof_verify_wrong_root,
    ));
    suite.add(TestCase::new("state_manager_new", state::test_state_manager_new));
    suite.add(TestCase::new("state_manager_default", state::test_state_manager_default));
    suite.add(TestCase::new(
        "state_manager_get_account_nonexistent",
        state::test_state_manager_get_account_nonexistent,
    ));
    suite.add(TestCase::new(
        "state_manager_get_balance_nonexistent",
        state::test_state_manager_get_balance_nonexistent,
    ));
    suite.add(TestCase::new(
        "state_manager_get_nonce_nonexistent",
        state::test_state_manager_get_nonce_nonexistent,
    ));
    suite.add(TestCase::new("state_manager_set_balance", state::test_state_manager_set_balance));
    suite.add(TestCase::new(
        "state_manager_increment_nonce",
        state::test_state_manager_increment_nonce,
    ));
    suite.add(TestCase::new(
        "state_manager_increment_nonce_nonexistent",
        state::test_state_manager_increment_nonce_nonexistent,
    ));
    suite.add(TestCase::new("state_manager_transfer", state::test_state_manager_transfer));
    suite.add(TestCase::new(
        "state_manager_transfer_insufficient_balance",
        state::test_state_manager_transfer_insufficient_balance,
    ));
    suite.add(TestCase::new(
        "state_manager_state_root_changes",
        state::test_state_manager_state_root_changes,
    ));
    suite
        .add(TestCase::new("state_manager_advance_block", state::test_state_manager_advance_block));
    suite
        .add(TestCase::new("state_manager_advance_batch", state::test_state_manager_advance_batch));
    suite.add(TestCase::new("account_storage_new", state::test_account_storage_new));
    suite.add(TestCase::new("account_storage_default", state::test_account_storage_default));
    suite.add(TestCase::new(
        "account_storage_get_nonexistent",
        state::test_account_storage_get_nonexistent,
    ));
    suite.add(TestCase::new("account_storage_exists", state::test_account_storage_exists));
    suite.add(TestCase::new(
        "account_storage_get_or_create",
        state::test_account_storage_get_or_create,
    ));
    suite.add(TestCase::new("account_storage_balance", state::test_account_storage_balance));
    suite.add(TestCase::new("account_storage_nonce", state::test_account_storage_nonce));
    suite.add(TestCase::new(
        "account_storage_increment_nonce",
        state::test_account_storage_increment_nonce,
    ));
    suite.add(TestCase::new("account_storage_len", state::test_account_storage_len));
    suite.add(TestCase::new("account_storage_iter", state::test_account_storage_iter));
    suite.add(TestCase::new("contract_storage_new", state::test_contract_storage_new));
    suite.add(TestCase::new("contract_storage_default", state::test_contract_storage_default));
    suite.add(TestCase::new(
        "contract_storage_get_nonexistent",
        state::test_contract_storage_get_nonexistent,
    ));
    suite.add(TestCase::new("contract_storage_set_get", state::test_contract_storage_set_get));
    suite.add(TestCase::new(
        "contract_storage_set_zero_removes",
        state::test_contract_storage_set_zero_removes,
    ));
    suite.add(TestCase::new("contract_storage_remove", state::test_contract_storage_remove));
    suite.add(TestCase::new(
        "contract_storage_remove_nonexistent",
        state::test_contract_storage_remove_nonexistent,
    ));
    suite.add(TestCase::new(
        "contract_storage_clear_account",
        state::test_contract_storage_clear_account,
    ));
    suite.add(TestCase::new(
        "contract_storage_iter_account",
        state::test_contract_storage_iter_account,
    ));
    suite.add(TestCase::new(
        "contract_storage_multiple_accounts",
        state::test_contract_storage_multiple_accounts,
    ));

    // Types tests (62)
    suite.add(TestCase::new("address_zero", types::test_address_zero));
    suite.add(TestCase::new("address_from_bytes_valid", types::test_address_from_bytes_valid));
    suite.add(TestCase::new(
        "address_from_bytes_invalid_length",
        types::test_address_from_bytes_invalid_length,
    ));
    suite.add(TestCase::new("address_from_slice", types::test_address_from_slice));
    suite.add(TestCase::new("address_as_bytes", types::test_address_as_bytes));
    suite.add(TestCase::new("address_from_array", types::test_address_from_array));
    suite.add(TestCase::new("address_as_ref", types::test_address_as_ref));
    suite.add(TestCase::new("address_debug_format", types::test_address_debug_format));
    suite.add(TestCase::new("address_equality", types::test_address_equality));
    suite.add(TestCase::new("address_ordering", types::test_address_ordering));
    suite.add(TestCase::new("address_default", types::test_address_default));
    suite.add(TestCase::new("u256_zero", types::test_u256_zero));
    suite.add(TestCase::new("u256_one", types::test_u256_one));
    suite.add(TestCase::new("u256_from_u64", types::test_u256_from_u64));
    suite.add(TestCase::new("u256_from_bytes_be", types::test_u256_from_bytes_be));
    suite.add(TestCase::new("u256_to_bytes_be", types::test_u256_to_bytes_be));
    suite.add(TestCase::new("u256_roundtrip", types::test_u256_roundtrip));
    suite.add(TestCase::new("u256_checked_add", types::test_u256_checked_add));
    suite.add(TestCase::new("u256_checked_add_overflow", types::test_u256_checked_add_overflow));
    suite.add(TestCase::new("u256_checked_sub", types::test_u256_checked_sub));
    suite.add(TestCase::new("u256_checked_sub_underflow", types::test_u256_checked_sub_underflow));
    suite.add(TestCase::new("u256_is_zero", types::test_u256_is_zero));
    suite.add(TestCase::new("u256_debug_format", types::test_u256_debug_format));
    suite.add(TestCase::new("u256_equality", types::test_u256_equality));
    suite.add(TestCase::new("u256_ordering", types::test_u256_ordering));
    suite.add(TestCase::new("batch_number_default", types::test_batch_number_default));
    suite.add(TestCase::new("batch_number_equality", types::test_batch_number_equality));
    suite.add(TestCase::new("batch_number_ordering", types::test_batch_number_ordering));
    suite.add(TestCase::new("block_number_default", types::test_block_number_default));
    suite.add(TestCase::new("block_number_equality", types::test_block_number_equality));
    suite.add(TestCase::new("nonce_default", types::test_nonce_default));
    suite.add(TestCase::new("nonce_increment", types::test_nonce_increment));
    suite.add(TestCase::new("nonce_increment_saturating", types::test_nonce_increment_saturating));
    suite.add(TestCase::new("gas_default", types::test_gas_default));
    suite.add(TestCase::new("gas_equality", types::test_gas_equality));
    suite.add(TestCase::new("tx_hash_zero", types::test_tx_hash_zero));
    suite.add(TestCase::new("tx_hash_from_bytes", types::test_tx_hash_from_bytes));
    suite.add(TestCase::new("tx_hash_as_bytes", types::test_tx_hash_as_bytes));
    suite.add(TestCase::new("tx_hash_from_array", types::test_tx_hash_from_array));
    suite.add(TestCase::new("tx_hash_debug_format", types::test_tx_hash_debug_format));
    suite.add(TestCase::new("tx_hash_equality", types::test_tx_hash_equality));
    suite.add(TestCase::new(
        "transaction_signature_default",
        types::test_transaction_signature_default,
    ));
    suite.add(TestCase::new("transaction_status_pending", types::test_transaction_status_pending));
    suite
        .add(TestCase::new("transaction_status_included", types::test_transaction_status_included));
    suite.add(TestCase::new(
        "transaction_status_committed",
        types::test_transaction_status_committed,
    ));
    suite.add(TestCase::new("transaction_status_proven", types::test_transaction_status_proven));
    suite.add(TestCase::new(
        "transaction_status_finalized",
        types::test_transaction_status_finalized,
    ));
    suite.add(TestCase::new("transaction_status_failed", types::test_transaction_status_failed));
    suite.add(TestCase::new("tx_fail_reason_variants", types::test_tx_fail_reason_variants));
    suite.add(TestCase::new("account_state_default", types::test_account_state_default));
    suite.add(TestCase::new(
        "account_state_empty_code_hash",
        types::test_account_state_empty_code_hash,
    ));
    suite
        .add(TestCase::new("account_state_is_empty_true", types::test_account_state_is_empty_true));
    suite.add(TestCase::new(
        "account_state_is_empty_false_nonce",
        types::test_account_state_is_empty_false_nonce,
    ));
    suite.add(TestCase::new(
        "account_state_is_empty_false_balance",
        types::test_account_state_is_empty_false_balance,
    ));
    suite.add(TestCase::new(
        "account_state_is_empty_false_code",
        types::test_account_state_is_empty_false_code,
    ));
    suite.add(TestCase::new("l2_block_clone", types::test_l2_block_clone));
    suite.add(TestCase::new("batch_clone", types::test_batch_clone));

    // Total: 263 tests
    suite.run()
}
