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

//! ELF subsystem tests
//!
//! Tests for ELF parsing, loading, ASLR, and dynamic linking.

use crate::elf::*;
use crate::test::framework::{TestCase, TestResult, TestSuite};

/// Run all ELF tests
pub fn run_all() -> bool {
    let mut suite = TestSuite::new("ELF");

    suite.add(TestCase::with_category("elf_magic_constant", test_elf_magic_constant, "elf"));
    suite.add(TestCase::with_category("elf_header_size", test_elf_header_size, "elf"));
    suite.add(TestCase::with_category("program_header_size", test_program_header_size, "elf"));
    suite.add(TestCase::with_category("section_header_size", test_section_header_size, "elf"));
    suite.add(TestCase::with_category("aslr_manager_creation", test_aslr_manager_creation, "elf"));
    suite.add(TestCase::with_category("aslr_disabled", test_aslr_disabled, "elf"));
    suite.add(TestCase::with_category("elf_class_values", test_elf_class_values, "elf"));
    suite.add(TestCase::with_category("elf_type_values", test_elf_type_values, "elf"));
    suite.add(TestCase::with_category("elf_machine_values", test_elf_machine_values, "elf"));
    suite.add(TestCase::with_category("phdr_type_values", test_phdr_type_values, "elf"));
    suite.add(TestCase::with_category("validate_elf_magic", test_validate_elf_magic, "elf"));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

pub(crate) fn test_elf_magic_constant() -> TestResult {
    if ELF_MAGIC != [0x7f, b'E', b'L', b'F'] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_header_size() -> TestResult {
    if core::mem::size_of::<ElfHeader>() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_program_header_size() -> TestResult {
    if core::mem::size_of::<ProgramHeader>() != 56 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_size() -> TestResult {
    if core::mem::size_of::<SectionHeader>() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aslr_manager_creation() -> TestResult {
    let manager = AslrManager::new();
    if !manager.is_executable_randomization_enabled() {
        return TestResult::Fail;
    }
    if !manager.is_stack_randomization_enabled() {
        return TestResult::Fail;
    }
    if !manager.is_heap_randomization_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aslr_disabled() -> TestResult {
    let manager = AslrManager::disabled();
    if manager.is_executable_randomization_enabled() {
        return TestResult::Fail;
    }
    if manager.is_stack_randomization_enabled() {
        return TestResult::Fail;
    }
    if manager.is_heap_randomization_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_class_values() -> TestResult {
    if elf_class::NONE != 0 {
        return TestResult::Fail;
    }
    if elf_class::CLASS32 != 1 {
        return TestResult::Fail;
    }
    if elf_class::CLASS64 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_type_values() -> TestResult {
    if elf_type::NONE != 0 {
        return TestResult::Fail;
    }
    if elf_type::REL != 1 {
        return TestResult::Fail;
    }
    if elf_type::EXEC != 2 {
        return TestResult::Fail;
    }
    if elf_type::DYN != 3 {
        return TestResult::Fail;
    }
    if elf_type::CORE != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_machine_values() -> TestResult {
    if elf_machine::NONE != 0 {
        return TestResult::Fail;
    }
    if elf_machine::X86_64 != 62 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_phdr_type_values() -> TestResult {
    if phdr_type::NULL != 0 {
        return TestResult::Fail;
    }
    if phdr_type::LOAD != 1 {
        return TestResult::Fail;
    }
    if phdr_type::DYNAMIC != 2 {
        return TestResult::Fail;
    }
    if phdr_type::INTERP != 3 {
        return TestResult::Fail;
    }
    if phdr_type::NOTE != 4 {
        return TestResult::Fail;
    }
    if phdr_type::PHDR != 6 {
        return TestResult::Fail;
    }
    if phdr_type::TLS != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_elf_magic() -> TestResult {
    let valid_header: [u8; 16] = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if !validate_elf(&valid_header) {
        return TestResult::Fail;
    }

    let invalid_header: [u8; 16] = [0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if validate_elf(&invalid_header) {
        return TestResult::Fail;
    }

    TestResult::Pass
}
