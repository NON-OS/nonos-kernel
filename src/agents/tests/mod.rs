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

//! Agent subsystem tests for NONOS kernel test framework.
//!
//! ## Pattern for Subsystem Tests
//!
//! Each subsystem must follow this pattern to integrate with the kernel test runner:
//!
//! 1. Create a `tests/` directory inside your subsystem (e.g., `src/mysubsystem/tests/`)
//! 2. Create test files with public functions that return `TestResult`
//! 3. Create a `mod.rs` that:
//!    - Declares all test modules as `pub mod`
//!    - Exports a `run_all() -> bool` function
//! 4. Use `TestSuite` and `TestCase` from `crate::test::framework`
//! 5. Register in `src/test/runner.rs` by calling your `run_all()` function

pub mod core_tests;
pub mod context_tests;
pub mod memory_tests;
pub mod tasks_tests;
pub mod scheduler_tests;
pub mod registry_tests;
pub mod presets_tests;
pub mod tools_tests;

use crate::test::framework::{TestCase, TestSuite};

/// Run all agent subsystem tests.
/// Returns true if all tests pass.
pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Agents");

    // Core tests
    suite.add_test(TestCase::new("agent_state_variants", core_tests::test_agent_state_variants, "agents/core"));
    suite.add_test(TestCase::new("message_role_variants", core_tests::test_message_role_variants, "agents/core"));
    suite.add_test(TestCase::new("agent_config_default", core_tests::test_agent_config_default, "agents/core"));
    suite.add_test(TestCase::new("agent_config_custom", core_tests::test_agent_config_custom, "agents/core"));
    suite.add_test(TestCase::new("agent_new", core_tests::test_agent_new, "agents/core"));
    suite.add_test(TestCase::new("agent_with_custom_config", core_tests::test_agent_with_custom_config, "agents/core"));
    suite.add_test(TestCase::new("agent_name_extraction", core_tests::test_agent_name_extraction, "agents/core"));
    suite.add_test(TestCase::new("agent_add_message", core_tests::test_agent_add_message, "agents/core"));
    suite.add_test(TestCase::new("agent_multiple_messages", core_tests::test_agent_multiple_messages, "agents/core"));
    suite.add_test(TestCase::new("agent_clear_messages", core_tests::test_agent_clear_messages, "agents/core"));
    suite.add_test(TestCase::new("agent_state_changes", core_tests::test_agent_state_changes, "agents/core"));
    suite.add_test(TestCase::new("agent_output", core_tests::test_agent_output, "agents/core"));
    suite.add_test(TestCase::new("agent_clone", core_tests::test_agent_clone, "agents/core"));
    suite.add_test(TestCase::new("agent_config_clone", core_tests::test_agent_config_clone, "agents/core"));
    suite.add_test(TestCase::new("agent_message_clone", core_tests::test_agent_message_clone, "agents/core"));
    suite.add_test(TestCase::new("agent_tools_enabled", core_tests::test_agent_tools_enabled, "agents/core"));
    suite.add_test(TestCase::new("agent_unique_ids", core_tests::test_agent_unique_ids, "agents/core"));
    suite.add_test(TestCase::new("agent_empty_name", core_tests::test_agent_empty_name, "agents/core"));

    // Context tests
    suite.add_test(TestCase::new("context_new", context_tests::test_context_new, "agents/context"));
    suite.add_test(TestCase::new("context_new_different_ids", context_tests::test_context_new_different_ids, "agents/context"));
    suite.add_test(TestCase::new("context_set_env_new_key", context_tests::test_context_set_env_new_key, "agents/context"));
    suite.add_test(TestCase::new("context_set_env_update_existing", context_tests::test_context_set_env_update_existing, "agents/context"));
    suite.add_test(TestCase::new("context_set_env_multiple_keys", context_tests::test_context_set_env_multiple_keys, "agents/context"));
    suite.add_test(TestCase::new("context_get_env_existing", context_tests::test_context_get_env_existing, "agents/context"));
    suite.add_test(TestCase::new("context_get_env_nonexistent", context_tests::test_context_get_env_nonexistent, "agents/context"));
    suite.add_test(TestCase::new("context_get_env_empty_value", context_tests::test_context_get_env_empty_value, "agents/context"));
    suite.add_test(TestCase::new("context_add_history", context_tests::test_context_add_history, "agents/context"));
    suite.add_test(TestCase::new("context_history_limit", context_tests::test_context_history_limit, "agents/context"));
    suite.add_test(TestCase::new("context_history_fifo_eviction", context_tests::test_context_history_fifo_eviction, "agents/context"));
    suite.add_test(TestCase::new("context_enable_tool", context_tests::test_context_enable_tool, "agents/context"));
    suite.add_test(TestCase::new("context_enable_tool_out_of_bounds", context_tests::test_context_enable_tool_out_of_bounds, "agents/context"));
    suite.add_test(TestCase::new("context_disable_tool", context_tests::test_context_disable_tool, "agents/context"));
    suite.add_test(TestCase::new("context_disable_tool_out_of_bounds", context_tests::test_context_disable_tool_out_of_bounds, "agents/context"));
    suite.add_test(TestCase::new("context_is_tool_enabled", context_tests::test_context_is_tool_enabled, "agents/context"));
    suite.add_test(TestCase::new("context_is_tool_enabled_out_of_bounds", context_tests::test_context_is_tool_enabled_out_of_bounds, "agents/context"));
    suite.add_test(TestCase::new("context_multiple_tools", context_tests::test_context_multiple_tools, "agents/context"));
    suite.add_test(TestCase::new("context_clone", context_tests::test_context_clone, "agents/context"));
    suite.add_test(TestCase::new("context_working_dir_default", context_tests::test_context_working_dir_default, "agents/context"));
    suite.add_test(TestCase::new("context_working_dir_modification", context_tests::test_context_working_dir_modification, "agents/context"));
    suite.add_test(TestCase::new("context_env_binary_values", context_tests::test_context_env_binary_values, "agents/context"));

    // Memory tests
    suite.add_test(TestCase::new("memory_new", memory_tests::test_memory_new, "agents/memory"));
    suite.add_test(TestCase::new("memory_store_and_recall", memory_tests::test_memory_store_and_recall, "agents/memory"));
    suite.add_test(TestCase::new("memory_recall_nonexistent", memory_tests::test_memory_recall_nonexistent, "agents/memory"));
    suite.add_test(TestCase::new("memory_store_update_existing", memory_tests::test_memory_store_update_existing, "agents/memory"));
    suite.add_test(TestCase::new("memory_multiple_keys", memory_tests::test_memory_multiple_keys, "agents/memory"));
    suite.add_test(TestCase::new("memory_isolation_between_agents", memory_tests::test_memory_isolation_between_agents, "agents/memory"));
    suite.add_test(TestCase::new("memory_search_basic", memory_tests::test_memory_search_basic, "agents/memory"));
    suite.add_test(TestCase::new("memory_search_no_results", memory_tests::test_memory_search_no_results, "agents/memory"));
    suite.add_test(TestCase::new("memory_search_empty_query", memory_tests::test_memory_search_empty_query, "agents/memory"));
    suite.add_test(TestCase::new("memory_search_isolation", memory_tests::test_memory_search_isolation, "agents/memory"));
    suite.add_test(TestCase::new("memory_recent", memory_tests::test_memory_recent, "agents/memory"));
    suite.add_test(TestCase::new("memory_recent_more_than_available", memory_tests::test_memory_recent_more_than_available, "agents/memory"));
    suite.add_test(TestCase::new("memory_recent_zero", memory_tests::test_memory_recent_zero, "agents/memory"));
    suite.add_test(TestCase::new("memory_recent_isolation", memory_tests::test_memory_recent_isolation, "agents/memory"));
    suite.add_test(TestCase::new("memory_importance_stored", memory_tests::test_memory_importance_stored, "agents/memory"));
    suite.add_test(TestCase::new("memory_key_truncation", memory_tests::test_memory_key_truncation, "agents/memory"));
    suite.add_test(TestCase::new("memory_entry_timestamp", memory_tests::test_memory_entry_timestamp, "agents/memory"));
    suite.add_test(TestCase::new("memory_entry_clone", memory_tests::test_memory_entry_clone, "agents/memory"));
    suite.add_test(TestCase::new("memory_empty_value", memory_tests::test_memory_empty_value, "agents/memory"));
    suite.add_test(TestCase::new("memory_large_value", memory_tests::test_memory_large_value, "agents/memory"));
    suite.add_test(TestCase::new("memory_max_entries_constant", memory_tests::test_memory_max_entries_constant, "agents/memory"));
    suite.add_test(TestCase::new("memory_binary_key", memory_tests::test_memory_binary_key, "agents/memory"));
    suite.add_test(TestCase::new("memory_binary_value", memory_tests::test_memory_binary_value, "agents/memory"));
    suite.add_test(TestCase::new("memory_search_partial_match", memory_tests::test_memory_search_partial_match, "agents/memory"));

    // Tasks tests
    suite.add_test(TestCase::new("create_task", tasks_tests::test_create_task, "agents/tasks"));
    suite.add_test(TestCase::new("create_task_unique_ids", tasks_tests::test_create_task_unique_ids, "agents/tasks"));
    suite.add_test(TestCase::new("get_task", tasks_tests::test_get_task, "agents/tasks"));
    suite.add_test(TestCase::new("get_task_nonexistent", tasks_tests::test_get_task_nonexistent, "agents/tasks"));
    suite.add_test(TestCase::new("task_status_variants", tasks_tests::test_task_status_variants, "agents/tasks"));
    suite.add_test(TestCase::new("update_task_status_running", tasks_tests::test_update_task_status_running, "agents/tasks"));
    suite.add_test(TestCase::new("update_task_status_complete", tasks_tests::test_update_task_status_complete, "agents/tasks"));
    suite.add_test(TestCase::new("update_task_status_failed", tasks_tests::test_update_task_status_failed, "agents/tasks"));
    suite.add_test(TestCase::new("list_agent_tasks", tasks_tests::test_list_agent_tasks, "agents/tasks"));
    suite.add_test(TestCase::new("list_agent_tasks_empty", tasks_tests::test_list_agent_tasks_empty, "agents/tasks"));
    suite.add_test(TestCase::new("pending_tasks", tasks_tests::test_pending_tasks, "agents/tasks"));
    suite.add_test(TestCase::new("cancel_task_pending", tasks_tests::test_cancel_task_pending, "agents/tasks"));
    suite.add_test(TestCase::new("cancel_task_already_running", tasks_tests::test_cancel_task_already_running, "agents/tasks"));
    suite.add_test(TestCase::new("cancel_task_nonexistent", tasks_tests::test_cancel_task_nonexistent, "agents/tasks"));
    suite.add_test(TestCase::new("task_timestamps", tasks_tests::test_task_timestamps, "agents/tasks"));
    suite.add_test(TestCase::new("task_clone", tasks_tests::test_task_clone, "agents/tasks"));
    suite.add_test(TestCase::new("max_tasks_constant", tasks_tests::test_max_tasks_constant, "agents/tasks"));
    suite.add_test(TestCase::new("task_empty_description", tasks_tests::test_task_empty_description, "agents/tasks"));
    suite.add_test(TestCase::new("task_large_description", tasks_tests::test_task_large_description, "agents/tasks"));
    suite.add_test(TestCase::new("update_nonexistent_task", tasks_tests::test_update_nonexistent_task, "agents/tasks"));
    suite.add_test(TestCase::new("task_result_empty", tasks_tests::test_task_result_empty, "agents/tasks"));
    suite.add_test(TestCase::new("task_multiple_status_updates", tasks_tests::test_task_multiple_status_updates, "agents/tasks"));

    // Scheduler tests
    suite.add_test(TestCase::new("schedule_once", scheduler_tests::test_schedule_once, "agents/scheduler"));
    suite.add_test(TestCase::new("schedule_once_unique_ids", scheduler_tests::test_schedule_once_unique_ids, "agents/scheduler"));
    suite.add_test(TestCase::new("schedule_repeat", scheduler_tests::test_schedule_repeat, "agents/scheduler"));
    suite.add_test(TestCase::new("schedule_repeat_unique_ids", scheduler_tests::test_schedule_repeat_unique_ids, "agents/scheduler"));
    suite.add_test(TestCase::new("cancel_schedule", scheduler_tests::test_cancel_schedule, "agents/scheduler"));
    suite.add_test(TestCase::new("cancel_schedule_nonexistent", scheduler_tests::test_cancel_schedule_nonexistent, "agents/scheduler"));
    suite.add_test(TestCase::new("cancel_schedule_already_cancelled", scheduler_tests::test_cancel_schedule_already_cancelled, "agents/scheduler"));
    suite.add_test(TestCase::new("list_scheduled", scheduler_tests::test_list_scheduled, "agents/scheduler"));
    suite.add_test(TestCase::new("list_scheduled_empty", scheduler_tests::test_list_scheduled_empty, "agents/scheduler"));
    suite.add_test(TestCase::new("list_scheduled_excludes_cancelled", scheduler_tests::test_list_scheduled_excludes_cancelled, "agents/scheduler"));
    suite.add_test(TestCase::new("active_count", scheduler_tests::test_active_count, "agents/scheduler"));
    suite.add_test(TestCase::new("max_scheduled_constant", scheduler_tests::test_max_scheduled_constant, "agents/scheduler"));
    suite.add_test(TestCase::new("scheduled_run_fields", scheduler_tests::test_scheduled_run_fields, "agents/scheduler"));
    suite.add_test(TestCase::new("scheduled_repeat_fields", scheduler_tests::test_scheduled_repeat_fields, "agents/scheduler"));
    suite.add_test(TestCase::new("scheduled_clone", scheduler_tests::test_scheduled_clone, "agents/scheduler"));
    suite.add_test(TestCase::new("schedule_empty_prompt", scheduler_tests::test_schedule_empty_prompt, "agents/scheduler"));
    suite.add_test(TestCase::new("schedule_large_prompt", scheduler_tests::test_schedule_large_prompt, "agents/scheduler"));
    suite.add_test(TestCase::new("schedule_zero_interval", scheduler_tests::test_schedule_zero_interval, "agents/scheduler"));
    suite.add_test(TestCase::new("schedule_large_interval", scheduler_tests::test_schedule_large_interval, "agents/scheduler"));
    suite.add_test(TestCase::new("mixed_scheduling", scheduler_tests::test_mixed_scheduling, "agents/scheduler"));

    // Registry tests
    suite.add_test(TestCase::new("create_agent", registry_tests::test_create_agent, "agents/registry"));
    suite.add_test(TestCase::new("create_agent_unique_ids", registry_tests::test_create_agent_unique_ids, "agents/registry"));
    suite.add_test(TestCase::new("get_agent", registry_tests::test_get_agent, "agents/registry"));
    suite.add_test(TestCase::new("get_agent_nonexistent", registry_tests::test_get_agent_nonexistent, "agents/registry"));
    suite.add_test(TestCase::new("with_agent_mut", registry_tests::test_with_agent_mut, "agents/registry"));
    suite.add_test(TestCase::new("with_agent_mut_nonexistent", registry_tests::test_with_agent_mut_nonexistent, "agents/registry"));
    suite.add_test(TestCase::new("update_agent", registry_tests::test_update_agent, "agents/registry"));
    suite.add_test(TestCase::new("update_agent_nonexistent", registry_tests::test_update_agent_nonexistent, "agents/registry"));
    suite.add_test(TestCase::new("list_agents", registry_tests::test_list_agents, "agents/registry"));
    suite.add_test(TestCase::new("delete_agent", registry_tests::test_delete_agent, "agents/registry"));
    suite.add_test(TestCase::new("delete_agent_nonexistent", registry_tests::test_delete_agent_nonexistent, "agents/registry"));
    suite.add_test(TestCase::new("delete_agent_twice", registry_tests::test_delete_agent_twice, "agents/registry"));
    suite.add_test(TestCase::new("agent_count", registry_tests::test_agent_count, "agents/registry"));
    suite.add_test(TestCase::new("max_agents_constant", registry_tests::test_max_agents_constant, "agents/registry"));
    suite.add_test(TestCase::new("agent_config_preserved", registry_tests::test_agent_config_preserved, "agents/registry"));
    suite.add_test(TestCase::new("list_agents_returns_id_and_name", registry_tests::test_list_agents_returns_id_and_name, "agents/registry"));
    suite.add_test(TestCase::new("agent_isolation", registry_tests::test_agent_isolation, "agents/registry"));
    suite.add_test(TestCase::new("multiple_operations", registry_tests::test_multiple_operations, "agents/registry"));

    // Presets tests
    suite.add_test(TestCase::new("coding_assistant_preset", presets_tests::test_coding_assistant_preset, "agents/presets"));
    suite.add_test(TestCase::new("file_manager_preset", presets_tests::test_file_manager_preset, "agents/presets"));
    suite.add_test(TestCase::new("system_monitor_preset", presets_tests::test_system_monitor_preset, "agents/presets"));
    suite.add_test(TestCase::new("web_researcher_preset", presets_tests::test_web_researcher_preset, "agents/presets"));
    suite.add_test(TestCase::new("task_automator_preset", presets_tests::test_task_automator_preset, "agents/presets"));
    suite.add_test(TestCase::new("list_presets", presets_tests::test_list_presets, "agents/presets"));
    suite.add_test(TestCase::new("list_presets_names", presets_tests::test_list_presets_names, "agents/presets"));
    suite.add_test(TestCase::new("list_presets_callable", presets_tests::test_list_presets_callable, "agents/presets"));
    suite.add_test(TestCase::new("preset_default_max_tokens", presets_tests::test_preset_default_max_tokens, "agents/presets"));
    suite.add_test(TestCase::new("preset_default_temperature", presets_tests::test_preset_default_temperature, "agents/presets"));
    suite.add_test(TestCase::new("presets_are_independent", presets_tests::test_presets_are_independent, "agents/presets"));
    suite.add_test(TestCase::new("preset_system_prompts_not_empty", presets_tests::test_preset_system_prompts_not_empty, "agents/presets"));
    suite.add_test(TestCase::new("preset_tool_configurations", presets_tests::test_preset_tool_configurations, "agents/presets"));

    // Tools tests
    suite.add_test(TestCase::new("register_tool", tools_tests::test_register_tool, "agents/tools"));
    suite.add_test(TestCase::new("register_tool_with_description", tools_tests::test_register_tool_with_description, "agents/tools"));
    suite.add_test(TestCase::new("execute_tool", tools_tests::test_execute_tool, "agents/tools"));
    suite.add_test(TestCase::new("execute_tool_with_args", tools_tests::test_execute_tool_with_args, "agents/tools"));
    suite.add_test(TestCase::new("execute_tool_not_found", tools_tests::test_execute_tool_not_found, "agents/tools"));
    suite.add_test(TestCase::new("execute_tool_transformation", tools_tests::test_execute_tool_transformation, "agents/tools"));
    suite.add_test(TestCase::new("list_tools", tools_tests::test_list_tools, "agents/tools"));
    suite.add_test(TestCase::new("list_tools_contains_registered", tools_tests::test_list_tools_contains_registered, "agents/tools"));
    suite.add_test(TestCase::new("max_tools_constant", tools_tests::test_max_tools_constant, "agents/tools"));
    suite.add_test(TestCase::new("tool_name_truncation", tools_tests::test_tool_name_truncation, "agents/tools"));
    suite.add_test(TestCase::new("tool_description_truncation", tools_tests::test_tool_description_truncation, "agents/tools"));
    suite.add_test(TestCase::new("execute_empty_args", tools_tests::test_execute_empty_args, "agents/tools"));
    suite.add_test(TestCase::new("execute_large_args", tools_tests::test_execute_large_args, "agents/tools"));
    suite.add_test(TestCase::new("tool_binary_args", tools_tests::test_tool_binary_args, "agents/tools"));
    suite.add_test(TestCase::new("multiple_tools", tools_tests::test_multiple_tools, "agents/tools"));
    suite.add_test(TestCase::new("tool_returns_empty", tools_tests::test_tool_returns_empty, "agents/tools"));
    suite.add_test(TestCase::new("list_tools_name_and_description", tools_tests::test_list_tools_name_and_description, "agents/tools"));

    let (_, failed, _) = suite.run_all();
    failed == 0
}
