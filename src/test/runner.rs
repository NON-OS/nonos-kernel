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

extern crate alloc;

use super::counters::{get_stats, reset_counters};
use super::{driver_tests, memory_tests, process_tests, security_tests};
use crate::agents::tests as agents_tests;
use crate::display::tests as display_tests;
use crate::drivers::ahci::tests as ahci_tests;
use crate::drivers::audio::tests as audio_tests;
use crate::drivers::e1000::tests as e1000_tests;
use crate::drivers::gpu::tests as gpu_tests;
use crate::drivers::nvme::tests as nvme_tests;
use crate::drivers::pci::tests as pci_tests;
use crate::drivers::rtl8139::tests as rtl8139_tests;
use crate::drivers::tpm::tests as tpm_tests;
use crate::drivers::usb::tests as usb_tests;
use crate::drivers::virtio_blk::tests as virtio_blk_tests;
use crate::drivers::virtio_net::tests as virtio_net_tests;
use crate::drivers::virtio_rng::tests as virtio_rng_tests;
use crate::drivers::wifi::tests as wifi_tests;
use crate::drivers::xhci::tests as xhci_tests;
use crate::elf::tests as elf_tests;
use crate::graphics::tests as graphics_tests;
use crate::input::tests as input_tests;
use crate::interrupts::tests as interrupts_tests;
use crate::ipc::tests as ipc_tests;
use crate::locale::tests as locale_tests;
use crate::log::tests as log_tests;
use crate::npkg::tests as npkg_tests;
use crate::process::tests as proc_tests;
use crate::runtime::tests as runtime_tests;
use crate::services::tests as services_tests;
use crate::shell::tests as shell_tests;
use crate::sys::tests as sys_tests;
use crate::usercopy::tests as usercopy_tests;
use crate::userspace::tests as userspace_tests;
use crate::vault::tests as vault_tests;
use crate::zk_engine::tests as zk_engine_tests;
use crate::zksync::tests as zksync_tests;

fn test_header(title: &str) {
    crate::sys::boot_log::test_header(title);
}

pub fn run_all_tests() -> bool {
    reset_counters();

    test_header("NONOS KERNEL TEST SUITE v0.8.4");

    let mut all_passed = true;

    test_header("SECURITY TESTS");
    if !security_tests::run_all() {
        all_passed = false;
    }

    test_header("DRIVER TESTS");
    if !driver_tests::run_all() {
        all_passed = false;
    }

    test_header("MEMORY TESTS");
    if !memory_tests::run_all() {
        all_passed = false;
    }

    test_header("PROCESS TESTS");
    if !process_tests::run_all() {
        all_passed = false;
    }

    test_header("AGENTS TESTS");
    if !agents_tests::run_all() {
        all_passed = false;
    }

    test_header("DISPLAY TESTS");
    if !display_tests::run_all() {
        all_passed = false;
    }

    test_header("AHCI TESTS");
    if !ahci_tests::run_all() {
        all_passed = false;
    }

    test_header("AUDIO TESTS");
    if !audio_tests::run_all() {
        all_passed = false;
    }

    test_header("E1000 TESTS");
    if !e1000_tests::run_all() {
        all_passed = false;
    }

    test_header("GPU TESTS");
    if !gpu_tests::run_all() {
        all_passed = false;
    }

    test_header("NVME TESTS");
    if !nvme_tests::run_all() {
        all_passed = false;
    }

    test_header("PCI TESTS");
    if !pci_tests::run_all() {
        all_passed = false;
    }

    test_header("RTL8139 TESTS");
    if !rtl8139_tests::run_all() {
        all_passed = false;
    }

    test_header("TPM TESTS");
    if !tpm_tests::run_all() {
        all_passed = false;
    }

    test_header("USB TESTS");
    if !usb_tests::run_all() {
        all_passed = false;
    }

    test_header("VIRTIO_BLK TESTS");
    if !virtio_blk_tests::run_all() {
        all_passed = false;
    }

    test_header("VIRTIO_NET TESTS");
    if !virtio_net_tests::run_all() {
        all_passed = false;
    }

    test_header("VIRTIO_RNG TESTS");
    if !virtio_rng_tests::run_all() {
        all_passed = false;
    }

    test_header("WIFI TESTS");
    if !wifi_tests::run_all() {
        all_passed = false;
    }

    test_header("XHCI TESTS");
    if !xhci_tests::run_all() {
        all_passed = false;
    }

    test_header("ELF TESTS");
    if !elf_tests::run_all() {
        all_passed = false;
    }

    test_header("GRAPHICS TESTS");
    if !graphics_tests::run_all() {
        all_passed = false;
    }

    test_header("INPUT TESTS");
    if !input_tests::run_all() {
        all_passed = false;
    }

    test_header("INTERRUPTS TESTS");
    if !interrupts_tests::run_all() {
        all_passed = false;
    }

    test_header("IPC TESTS");
    if !ipc_tests::run_all() {
        all_passed = false;
    }

    test_header("LOCALE TESTS");
    if !locale_tests::run_all() {
        all_passed = false;
    }

    test_header("LOG TESTS");
    if !log_tests::run_all() {
        all_passed = false;
    }

    test_header("NPKG TESTS");
    if !npkg_tests::run_all() {
        all_passed = false;
    }

    test_header("PROCESS TESTS");
    if !proc_tests::run_all() {
        all_passed = false;
    }

    test_header("RUNTIME TESTS");
    if !runtime_tests::run_all() {
        all_passed = false;
    }

    test_header("SERVICES TESTS");
    if !services_tests::run_all() {
        all_passed = false;
    }

    test_header("SHELL TESTS");
    if !shell_tests::run_all() {
        all_passed = false;
    }

    test_header("SYS TESTS");
    if !sys_tests::run_all() {
        all_passed = false;
    }

    test_header("USERCOPY TESTS");
    if !usercopy_tests::run_all() {
        all_passed = false;
    }

    test_header("USERSPACE TESTS");
    if !userspace_tests::run_all() {
        all_passed = false;
    }

    test_header("VAULT TESTS");
    if !vault_tests::run_all() {
        all_passed = false;
    }

    test_header("ZK_ENGINE TESTS");
    if !zk_engine_tests::run_all() {
        all_passed = false;
    }

    test_header("ZKSYNC TESTS");
    if !zksync_tests::run_all() {
        all_passed = false;
    }

    let (run, passed, failed, skipped) = get_stats();
    let summary = alloc::format!(
        "Total: {} | Passed: {} | Failed: {} | Skipped: {}",
        run,
        passed,
        failed,
        skipped
    );
    test_header(&summary);

    if all_passed && failed == 0 {
        crate::sys::boot_log::ok("TEST", "ALL TESTS PASSED");
    } else {
        crate::sys::boot_log::error("SOME TESTS FAILED");
    }

    all_passed && failed == 0
}
