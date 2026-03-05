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

//! Security subsystem tests
//!
//! Tests for capability system, process isolation, and security policies.

extern crate alloc;

use super::framework::{TestResult, TestCase, TestSuite};

/// Run all security tests
pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Security");

    suite.add_test(TestCase::new(
        "capability_types",
        test_capability_types,
        "security",
    ));
    suite.add_test(TestCase::new(
        "capability_token",
        test_capability_token,
        "security",
    ));
    suite.add_test(TestCase::new(
        "capability_bits",
        test_capability_bits,
        "security",
    ));
    suite.add_test(TestCase::new(
        "driver_access_control",
        test_driver_access_control,
        "security",
    ));
    suite.add_test(TestCase::new(
        "pci_validation",
        test_pci_validation,
        "security",
    ));
    suite.add_test(TestCase::new(
        "memory_protection",
        test_memory_protection,
        "security",
    ));

    let (_passed, failed, _) = suite.run_all();
    failed == 0
}

/// Test capability types
fn test_capability_types() -> TestResult {
    use crate::capabilities::Capability;

    // Test all capability types exist
    let caps = [
        Capability::CoreExec,
        Capability::IO,
        Capability::Network,
        Capability::IPC,
        Capability::Memory,
        Capability::Crypto,
        Capability::FileSystem,
        Capability::Hardware,
        Capability::Debug,
        Capability::Admin,
    ];

    // Verify all 10 capabilities are distinct
    for i in 0..caps.len() {
        for j in (i + 1)..caps.len() {
            if caps[i] == caps[j] {
                return TestResult::Fail;
            }
        }
    }

    TestResult::Pass
}

/// Test capability token functionality
fn test_capability_token() -> TestResult {
    use crate::capabilities::{Capability, has_signing_key};

    // Skip if signing key not set
    if !has_signing_key() {
        return TestResult::Skip;
    }

    // Test token creation
    match crate::capabilities::create_token(1, &[Capability::CoreExec], None) {
        Ok(token) => {
            // Verify token grants the capability
            if !token.grants(Capability::CoreExec) {
                return TestResult::Fail;
            }

            // Verify token doesn't grant other capabilities
            if token.grants(Capability::Admin) {
                return TestResult::Fail;
            }

            // Verify token validation
            if !token.is_valid() {
                return TestResult::Fail;
            }

            TestResult::Pass
        }
        Err(_) => TestResult::Fail,
    }
}

/// Test capability bit conversion
fn test_capability_bits() -> TestResult {
    use crate::capabilities::{Capability, caps_to_bits, bits_to_caps};

    let caps = [Capability::CoreExec, Capability::Memory, Capability::Admin];
    let bits = caps_to_bits(&caps);

    // Bits should be non-zero
    if bits == 0 {
        return TestResult::Fail;
    }

    // Round-trip test
    let restored = bits_to_caps(bits);

    // Should have same number of capabilities
    if restored.len() != caps.len() {
        return TestResult::Fail;
    }

    // All original capabilities should be in restored list
    for cap in &caps {
        if !restored.contains(cap) {
            return TestResult::Fail;
        }
    }

    TestResult::Pass
}

/// Test driver access control
fn test_driver_access_control() -> TestResult {
    use crate::drivers::security::{validate_pci_access, DriverError};

    // Test valid PCI access
    let result = validate_pci_access(0, 0, 0, 0);
    if result.is_err() {
        return TestResult::Fail;
    }

    // Test invalid device (32 is out of range, max is 31)
    let result = validate_pci_access(0, 32, 0, 0);
    match result {
        Err(DriverError::InvalidPciAccess) => {}
        _ => return TestResult::Fail,
    }

    // Test invalid function (8 is out of range, max is 7)
    let result = validate_pci_access(0, 0, 8, 0);
    match result {
        Err(DriverError::InvalidPciAccess) => {}
        _ => return TestResult::Fail,
    }

    TestResult::Pass
}

/// Test PCI config space validation
fn test_pci_validation() -> TestResult {
    use crate::drivers::security::is_config_write_allowed;

    // Test that function doesn't panic for various offsets
    for offset in (0..255u8).step_by(4) {
        let _ = is_config_write_allowed(offset);
    }

    TestResult::Pass
}

/// Test memory protection policies
fn test_memory_protection() -> TestResult {
    use crate::memory::MemoryProtection;

    // Test protection levels
    let none = MemoryProtection::None;
    let read = MemoryProtection::Read;
    let rw = MemoryProtection::ReadWrite;
    let rx = MemoryProtection::ReadExecute;

    // All should be distinct
    if none == read {
        return TestResult::Fail;
    }
    if read == rw {
        return TestResult::Fail;
    }
    if rw == rx {
        return TestResult::Fail;
    }
    if rx == none {
        return TestResult::Fail;
    }

    TestResult::Pass
}
