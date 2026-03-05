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

pub fn run_all_tests() -> bool {
    use crate::drivers::console;

    reset_counters();

    console::write_message("");
    console::write_message("╔═══════════════════════════════════════════════════════════════════╗");
    console::write_message("║           NONOS KERNEL TEST SUITE v0.8.0                          ║");
    console::write_message("║                 Security-Focused Testing                          ║");
    console::write_message("╚═══════════════════════════════════════════════════════════════════╝");
    console::write_message("");

    let mut all_passed = true;

    console::write_message("━━━━━━━━━━━━━━━ SECURITY TESTS ━━━━━━━━━━━━━━━");
    if !security_tests::run_all() {
        all_passed = false;
    }

    console::write_message("");
    console::write_message("━━━━━━━━━━━━━━━ DRIVER TESTS ━━━━━━━━━━━━━━━━━");
    if !driver_tests::run_all() {
        all_passed = false;
    }

    console::write_message("");
    console::write_message("━━━━━━━━━━━━━━━ MEMORY TESTS ━━━━━━━━━━━━━━━━━");
    if !memory_tests::run_all() {
        all_passed = false;
    }

    console::write_message("");
    console::write_message("━━━━━━━━━━━━━━━ PROCESS TESTS ━━━━━━━━━━━━━━━━");
    if !process_tests::run_all() {
        all_passed = false;
    }

    let (run, passed, failed, skipped) = get_stats();
    console::write_message("");
    console::write_message("╔═══════════════════════════════════════════════════════════════════╗");
    console::write_message("║                      TEST SUMMARY                                 ║");
    console::write_message("╠═══════════════════════════════════════════════════════════════════╣");
    console::write_message(&alloc::format!("║  Total:   {:>4}                                                    ║", run));
    console::write_message(&alloc::format!("║  Passed:  {:>4}  ✓                                                 ║", passed));
    console::write_message(&alloc::format!("║  Failed:  {:>4}  ✗                                                 ║", failed));
    console::write_message(&alloc::format!("║  Skipped: {:>4}  ⊘                                                 ║", skipped));
    console::write_message("╚═══════════════════════════════════════════════════════════════════╝");

    if all_passed && failed == 0 {
        console::write_message("");
        console::write_message("═══════════════════════════════════════════════════════════════════");
        console::write_message("                    ALL TESTS PASSED ✓                             ");
        console::write_message("═══════════════════════════════════════════════════════════════════");
    } else {
        console::write_message("");
        console::write_message("═══════════════════════════════════════════════════════════════════");
        console::write_message("                    SOME TESTS FAILED ✗                            ");
        console::write_message("═══════════════════════════════════════════════════════════════════");
    }

    all_passed && failed == 0
}
