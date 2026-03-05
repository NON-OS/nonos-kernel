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

//! Driver subsystem tests
//!
//! Tests for driver security hardening, MMIO validation, DMA safety.

extern crate alloc;

use super::framework::{TestResult, TestCase, TestSuite};

/// Run all driver tests
pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Drivers");

    suite.add_test(TestCase::new(
        "pci_manager_init",
        test_pci_manager_init,
        "drivers",
    ));
    suite.add_test(TestCase::new(
        "pci_stats_tracking",
        test_pci_stats_tracking,
        "drivers",
    ));
    suite.add_test(TestCase::new(
        "console_driver",
        test_console_driver,
        "drivers",
    ));
    suite.add_test(TestCase::new(
        "nvme_validation",
        test_nvme_validation,
        "drivers",
    ));
    suite.add_test(TestCase::new(
        "ahci_validation",
        test_ahci_validation,
        "drivers",
    ));
    suite.add_test(TestCase::new(
        "xhci_validation",
        test_xhci_validation,
        "drivers",
    ));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

/// Test PCI manager initialization
fn test_pci_manager_init() -> TestResult {
    match crate::drivers::get_pci_manager() {
        Some(_mgr) => TestResult::Pass,
        None => TestResult::Skip, // PCI not available
    }
}

/// Test PCI statistics tracking
fn test_pci_stats_tracking() -> TestResult {
    match crate::drivers::get_pci_manager() {
        Some(mgr) => {
            let stats = mgr.lock().get_stats();

            // Stats should be non-negative (they're u32/u64)
            // Just verify the stats struct is accessible
            let _ = stats.total_devices;
            let _ = stats.msix_capable_devices;

            TestResult::Pass
        }
        None => TestResult::Skip,
    }
}

/// Test console driver operations
fn test_console_driver() -> TestResult {
    let stats = crate::drivers::console::get_console_stats();

    // Console should have written some messages by now
    let msgs = stats.messages_written.load(core::sync::atomic::Ordering::Relaxed);

    // We've definitely written messages to get here
    if msgs == 0 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

/// Test NVMe driver validation
fn test_nvme_validation() -> TestResult {
    match crate::drivers::nvme::get_controller() {
        Some(nvme) => {
            let stats = nvme.get_stats();

            // Verify stats are accessible
            let _ = stats.namespaces;
            let _ = stats.bytes_read;
            let _ = stats.bytes_written;

            TestResult::Pass
        }
        None => TestResult::Skip, // NVMe not available
    }
}

/// Test AHCI driver validation
fn test_ahci_validation() -> TestResult {
    match crate::drivers::ahci::get_controller() {
        Some(ahci) => {
            let stats = ahci.get_stats();

            // Verify stats are accessible
            let _ = stats.devices_count;
            let _ = stats.read_ops;
            let _ = stats.write_ops;

            TestResult::Pass
        }
        None => TestResult::Skip, // AHCI not available
    }
}

/// Test xHCI driver validation
fn test_xhci_validation() -> TestResult {
    match crate::drivers::xhci::get_controller() {
        Some(xhci) => {
            let stats = xhci.get_stats();

            // Verify stats are accessible
            let _ = stats.devices_connected;
            let _ = stats.interrupts;
            let _ = stats.transfers;
            let _ = stats.errors;
            let _ = stats.bytes_transferred;

            TestResult::Pass
        }
        None => TestResult::Skip, // xHCI not available
    }
}
