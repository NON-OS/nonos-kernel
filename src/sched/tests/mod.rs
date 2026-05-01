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

mod context;
mod priority;
mod runqueue;
mod task;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("sched");

    // Context tests (22)
    suite.add(TestCase::new("context_struct_size", context::test_context_struct_size));
    suite.add(TestCase::new("context_is_repr_c", context::test_context_is_repr_c));
    suite.add(TestCase::new("context_copy", context::test_context_copy));
    suite.add(TestCase::new("context_clone", context::test_context_clone));
    suite.add(TestCase::new(
        "context_validate_valid_kernel",
        context::test_context_validate_valid_kernel,
    ));
    suite.add(TestCase::new(
        "context_validate_valid_userspace",
        context::test_context_validate_valid_userspace,
    ));
    suite.add(TestCase::new(
        "context_validate_noncanonical_rip",
        context::test_context_validate_noncanonical_rip,
    ));
    suite.add(TestCase::new(
        "context_validate_noncanonical_rsp",
        context::test_context_validate_noncanonical_rsp,
    ));
    suite.add(TestCase::new("context_validate_null_rsp", context::test_context_validate_null_rsp));
    suite.add(TestCase::new(
        "context_validate_userspace_valid",
        context::test_context_validate_userspace_valid,
    ));
    suite.add(TestCase::new(
        "context_validate_userspace_kernel_rip",
        context::test_context_validate_userspace_kernel_rip,
    ));
    suite.add(TestCase::new(
        "context_validate_userspace_kernel_rsp",
        context::test_context_validate_userspace_kernel_rsp,
    ));
    suite.add(TestCase::new(
        "context_validate_userspace_boundary_rip",
        context::test_context_validate_userspace_boundary_rip,
    ));
    suite.add(TestCase::new(
        "context_validate_userspace_over_boundary_rip",
        context::test_context_validate_userspace_over_boundary_rip,
    ));
    suite
        .add(TestCase::new("context_all_registers_zero", context::test_context_all_registers_zero));
    suite.add(TestCase::new(
        "context_with_custom_registers",
        context::test_context_with_custom_registers,
    ));
    suite.add(TestCase::new(
        "context_canonical_boundary_low",
        context::test_context_canonical_boundary_low,
    ));
    suite.add(TestCase::new(
        "context_canonical_boundary_high",
        context::test_context_canonical_boundary_high,
    ));
    suite.add(TestCase::new(
        "context_noncanonical_hole_low",
        context::test_context_noncanonical_hole_low,
    ));
    suite.add(TestCase::new(
        "context_noncanonical_hole_high",
        context::test_context_noncanonical_hole_high,
    ));

    // Priority tests (9)
    suite.add(TestCase::new("priority_values", priority::test_priority_values));
    suite.add(TestCase::new("priority_ordering", priority::test_priority_ordering));
    suite.add(TestCase::new("priority_equality", priority::test_priority_equality));
    suite.add(TestCase::new("priority_clone", priority::test_priority_clone));
    suite.add(TestCase::new("priority_copy", priority::test_priority_copy));
    suite.add(TestCase::new("priority_partial_ord", priority::test_priority_partial_ord));
    suite.add(TestCase::new("priority_debug", priority::test_priority_debug));
    suite.add(TestCase::new(
        "all_priority_variants_unique",
        priority::test_all_priority_variants_unique,
    ));
    suite.add(TestCase::new("priority_ord_consistency", priority::test_priority_ord_consistency));

    // RunQueue tests (20)
    suite.add(TestCase::new("runqueue_new", runqueue::test_runqueue_new));
    suite.add(TestCase::new("runqueue_push_single", runqueue::test_runqueue_push_single));
    suite.add(TestCase::new("runqueue_push_multiple", runqueue::test_runqueue_push_multiple));
    suite.add(TestCase::new("runqueue_pop_empty", runqueue::test_runqueue_pop_empty));
    suite.add(TestCase::new("runqueue_pop_single", runqueue::test_runqueue_pop_single));
    suite.add(TestCase::new("runqueue_fifo_order", runqueue::test_runqueue_fifo_order));
    suite.add(TestCase::new("runqueue_clear", runqueue::test_runqueue_clear));
    suite.add(TestCase::new("runqueue_clear_empty", runqueue::test_runqueue_clear_empty));
    suite.add(TestCase::new(
        "runqueue_is_empty_after_pop",
        runqueue::test_runqueue_is_empty_after_pop,
    ));
    suite.add(TestCase::new(
        "runqueue_len_after_operations",
        runqueue::test_runqueue_len_after_operations,
    ));
    suite.add(TestCase::new(
        "runqueue_remove_by_id_existing",
        runqueue::test_runqueue_remove_by_id_existing,
    ));
    suite.add(TestCase::new(
        "runqueue_remove_by_id_nonexistent",
        runqueue::test_runqueue_remove_by_id_nonexistent,
    ));
    suite.add(TestCase::new(
        "runqueue_remove_by_id_empty",
        runqueue::test_runqueue_remove_by_id_empty,
    ));
    suite.add(TestCase::new(
        "runqueue_remove_by_id_first",
        runqueue::test_runqueue_remove_by_id_first,
    ));
    suite.add(TestCase::new(
        "runqueue_remove_by_id_last",
        runqueue::test_runqueue_remove_by_id_last,
    ));
    suite.add(TestCase::new(
        "runqueue_remove_by_id_maintains_order",
        runqueue::test_runqueue_remove_by_id_maintains_order,
    ));
    suite.add(TestCase::new("runqueue_mixed_operations", runqueue::test_runqueue_mixed_operations));
    suite.add(TestCase::new("runqueue_push_after_clear", runqueue::test_runqueue_push_after_clear));
    suite.add(TestCase::new(
        "runqueue_large_number_of_tasks",
        runqueue::test_runqueue_large_number_of_tasks,
    ));

    // Task tests (32)
    suite.add(TestCase::new("task_spawn_creates_task", task::test_task_spawn_creates_task));
    suite.add(TestCase::new(
        "task_spawn_with_different_priorities",
        task::test_task_spawn_with_different_priorities,
    ));
    suite.add(TestCase::new("task_id_starts_at_zero", task::test_task_id_starts_at_zero));
    suite.add(TestCase::new("task_has_function", task::test_task_has_function));
    suite.add(TestCase::new(
        "task_is_complete_initially_false",
        task::test_task_is_complete_initially_false,
    ));
    suite.add(TestCase::new(
        "task_module_id_none_for_spawned",
        task::test_task_module_id_none_for_spawned,
    ));
    suite.add(TestCase::new(
        "task_entry_point_zero_for_spawned",
        task::test_task_entry_point_zero_for_spawned,
    ));
    suite.add(TestCase::new(
        "task_stack_pointer_zero_for_spawned",
        task::test_task_stack_pointer_zero_for_spawned,
    ));
    suite.add(TestCase::new(
        "new_module_task_low_priority",
        task::test_new_module_task_low_priority,
    ));
    suite.add(TestCase::new(
        "new_module_task_normal_priority",
        task::test_new_module_task_normal_priority,
    ));
    suite.add(TestCase::new(
        "new_module_task_high_priority",
        task::test_new_module_task_high_priority,
    ));
    suite.add(TestCase::new(
        "new_module_task_critical_priority",
        task::test_new_module_task_critical_priority,
    ));
    suite.add(TestCase::new(
        "new_module_task_realtime_priority",
        task::test_new_module_task_realtime_priority,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_50",
        task::test_new_module_task_priority_boundary_50,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_51",
        task::test_new_module_task_priority_boundary_51,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_100",
        task::test_new_module_task_priority_boundary_100,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_101",
        task::test_new_module_task_priority_boundary_101,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_150",
        task::test_new_module_task_priority_boundary_150,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_151",
        task::test_new_module_task_priority_boundary_151,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_200",
        task::test_new_module_task_priority_boundary_200,
    ));
    suite.add(TestCase::new(
        "new_module_task_priority_boundary_201",
        task::test_new_module_task_priority_boundary_201,
    ));
    suite.add(TestCase::new("new_module_task_name", task::test_new_module_task_name));
    suite.add(TestCase::new(
        "new_module_task_func_is_none",
        task::test_new_module_task_func_is_none,
    ));
    suite.add(TestCase::new(
        "new_module_task_not_complete",
        task::test_new_module_task_not_complete,
    ));
    suite.add(TestCase::new(
        "new_module_task_affinity_any",
        task::test_new_module_task_affinity_any,
    ));
    suite.add(TestCase::new("cpu_affinity_any", task::test_cpu_affinity_any));
    suite.add(TestCase::new("cpu_affinity_new_single", task::test_cpu_affinity_new_single));
    suite.add(TestCase::new("cpu_affinity_new_multiple", task::test_cpu_affinity_new_multiple));
    suite.add(TestCase::new("cpu_affinity_new_empty", task::test_cpu_affinity_new_empty));
    suite.add(TestCase::new("cpu_affinity_clone", task::test_cpu_affinity_clone));
    suite.add(TestCase::new("cpu_affinity_debug", task::test_cpu_affinity_debug));
    suite.add(TestCase::new("task_with_custom_affinity", task::test_task_with_custom_affinity));

    suite.run()
}
