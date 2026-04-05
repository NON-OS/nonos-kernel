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

pub mod commands;
pub mod constants_tests;
pub mod entry;
pub mod error;
pub mod namespace;
pub mod stats;
pub mod types;

use crate::test::framework::TestSuite;

pub fn run_all() -> TestSuite {
    let mut suite = TestSuite::new("nvme");

    // commands tests (7 tests)
    suite.add_test("test_build_identify_command", commands::test_build_identify_command);
    suite.add_test("test_build_read_command", commands::test_build_read_command);
    suite.add_test("test_build_write_command", commands::test_build_write_command);
    suite.add_test("test_build_flush_command", commands::test_build_flush_command);
    suite.add_test("test_build_dsm_command", commands::test_build_dsm_command);
    suite.add_test("test_build_create_cq_command", commands::test_build_create_cq_command);
    suite.add_test("test_build_create_sq_command", commands::test_build_create_sq_command);

    // constants_tests tests (5 tests)
    suite.add_test("test_constants", constants_tests::test_constants);
    suite.add_test("test_doorbell_calculation", constants_tests::test_doorbell_calculation);
    suite.add_test("test_cap_helpers", constants_tests::test_cap_helpers);
    suite.add_test("test_aqa_encoding", constants_tests::test_aqa_encoding);
    suite.add_test("test_version_parsing", constants_tests::test_version_parsing);

    // entry tests (5 tests)
    suite.add_test("test_submission_entry_creation", entry::test_submission_entry_creation);
    suite.add_test("test_submission_entry_opcode_cid", entry::test_submission_entry_opcode_cid);
    suite.add_test("test_submission_entry_sanitize", entry::test_submission_entry_sanitize);
    suite.add_test("test_completion_entry_status", entry::test_completion_entry_status);
    suite.add_test("test_completion_entry_error", entry::test_completion_entry_error);

    // error tests (3 tests)
    suite.add_test("test_error_display", error::test_error_display);
    suite.add_test("test_error_classification", error::test_error_classification);
    suite.add_test("test_status_code_parsing", error::test_status_code_parsing);

    // namespace tests (3 tests)
    suite.add_test("test_namespace_lba_validation", namespace::test_namespace_lba_validation);
    suite.add_test("test_namespace_manager", namespace::test_namespace_manager);
    suite.add_test("test_namespace_list_parsing", namespace::test_namespace_list_parsing);

    // stats tests (2 tests)
    suite.add_test("test_stats_atomic_operations", stats::test_stats_atomic_operations);
    suite.add_test("test_security_stats", stats::test_security_stats);

    // types tests (5 tests)
    suite.add_test("test_controller_capabilities", types::test_controller_capabilities);
    suite.add_test("test_controller_version", types::test_controller_version);
    suite.add_test("test_lba_format", types::test_lba_format);
    suite.add_test("test_lba_format_4k", types::test_lba_format_4k);
    suite.add_test("test_dsm_range", types::test_dsm_range);

    suite
}
