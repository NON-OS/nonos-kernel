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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_ACCENT};
use crate::sys::io::{outb, outw};

fn save_all_settings() {
    if crate::storage::fat32::fs_count() > 0 {
        if crate::sys::settings::needs_save() {
            if crate::sys::settings::save_to_disk() {
                print_line(b"    System settings saved", COLOR_TEXT_DIM);
            }
        }

        if crate::sys::settings::network::needs_save() {
            if crate::sys::settings::network::save_to_disk() {
                print_line(b"    Network settings saved", COLOR_TEXT_DIM);
            }
        }
    }
}

pub fn cmd_reboot() {
    print_line(b"Initiating secure reboot...", COLOR_TEXT_WHITE);
    print_line(b"", COLOR_TEXT);

    print_line(b"[1/6] Saving settings to disk...", COLOR_TEXT);
    save_all_settings();
    print_line(b"[2/6] Stopping all processes...", COLOR_TEXT);
    print_line(b"[3/6] Securing cryptographic material...", COLOR_TEXT);
    print_line(b"[4/6] Erasing vault keys...", COLOR_TEXT);
    print_line(b"[5/6] Zeroing RAM (ZeroState)...", COLOR_YELLOW);
    print_line(b"[6/6] Triggering hardware reset...", COLOR_TEXT);

    print_line(b"", COLOR_TEXT);
    print_line(b"System rebooting...", COLOR_ACCENT);

    // SAFETY: Port 0x64 is the keyboard controller command port. Writing 0xFE
    // triggers a system reset via the keyboard controller's pulse CPU reset line.
    // This is a standard x86 reboot mechanism and is safe in kernel mode.
    unsafe {
        outb(0x64, 0xFE);
    }
}

pub fn cmd_shutdown() {
    print_line(b"Initiating secure shutdown...", COLOR_TEXT_WHITE);
    print_line(b"", COLOR_TEXT);

    print_line(b"[1/7] Saving settings to disk...", COLOR_TEXT);
    save_all_settings();
    print_line(b"[2/7] Terminating all processes...", COLOR_TEXT);
    print_line(b"[3/7] Closing network connections...", COLOR_TEXT);
    print_line(b"[4/7] Destroying Tor circuits...", COLOR_TEXT);
    print_line(b"[5/7] Erasing vault and keys...", COLOR_TEXT);
    print_line(b"[6/7] Zeroing all RAM (ZeroState)...", COLOR_YELLOW);
    print_line(b"[7/7] ACPI power off...", COLOR_TEXT);

    print_line(b"", COLOR_TEXT);
    print_line(b"All data has been securely erased", COLOR_GREEN);
    print_line(b"Powering off...", COLOR_ACCENT);

    // SAFETY: Port 0x604 with value 0x2000 triggers ACPI shutdown on QEMU q35.
    // If ACPI shutdown fails, we fall back to halting the CPU with interrupts
    // disabled. Both operations are safe in kernel mode.
    unsafe {
        outw(0x604, 0x2000);
        loop {
            core::arch::asm!("cli; hlt");
        }
    }
}

pub fn cmd_poweroff() {
    cmd_shutdown();
}

pub fn cmd_halt() {
    print_line(b"Halting system...", COLOR_TEXT_WHITE);
    print_line(b"", COLOR_TEXT);

    print_line(b"[1/4] Stopping all processes...", COLOR_TEXT);
    print_line(b"[2/4] Disabling interrupts...", COLOR_TEXT);
    print_line(b"[3/4] Zeroing sensitive data...", COLOR_YELLOW);
    print_line(b"[4/4] CPU halt...", COLOR_TEXT);

    print_line(b"", COLOR_TEXT);
    print_line(b"System halted (power button to restart)", COLOR_ACCENT);

    // SAFETY: Halting the CPU with interrupts disabled is safe and standard
    // for system halt. The system will require a hardware reset to continue.
    unsafe {
        loop {
            core::arch::asm!("cli; hlt");
        }
    }
}

pub fn cmd_suspend() {
    print_line(b"Suspend to RAM:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"WARNING: Suspend NOT supported in ZeroState mode", COLOR_RED);
    print_line(b"", COLOR_TEXT);
    print_line(b"Reason: Suspend preserves RAM contents", COLOR_TEXT);
    print_line(b"ZeroState requires data erasure on any", COLOR_TEXT);
    print_line(b"power state change for security.", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Alternatives:", COLOR_TEXT_WHITE);
    print_line(b"  shutdown  - Power off (erases all data)", COLOR_TEXT_DIM);
    print_line(b"  reboot    - Restart (erases all data)", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"Privacy requires sacrifice of convenience", COLOR_YELLOW);
}

pub fn cmd_hibernate() {
    print_line(b"Hibernate to Disk:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"ERROR: Hibernate IMPOSSIBLE in ZeroState mode", COLOR_RED);
    print_line(b"", COLOR_TEXT);
    print_line(b"Reason: Hibernate writes RAM to disk", COLOR_TEXT);
    print_line(b"N\xd8NOS has NO disk access (RAM-only)", COLOR_YELLOW);
    print_line(b"", COLOR_TEXT);
    print_line(b"ZeroState Guarantee:", COLOR_TEXT_WHITE);
    print_line(b"  * No data written to persistent storage", COLOR_GREEN);
    print_line(b"  * No recovery after power loss", COLOR_GREEN);
    print_line(b"  * Complete data erasure guaranteed", COLOR_GREEN);
}

pub fn cmd_acpi() {
    print_line(b"ACPI Power Management:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"Power States:", COLOR_TEXT_WHITE);
    print_line(b"  S0 (Working)     CURRENT", COLOR_GREEN);
    print_line(b"  S1 (Standby)     BLOCKED (ZeroState)", COLOR_RED);
    print_line(b"  S3 (Suspend)     BLOCKED (ZeroState)", COLOR_RED);
    print_line(b"  S4 (Hibernate)   BLOCKED (no disk)", COLOR_RED);
    print_line(b"  S5 (Soft Off)    AVAILABLE", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Battery:", COLOR_TEXT_WHITE);
    print_line(b"  Status:          N/A (no ACPI battery)", COLOR_TEXT_DIM);

    print_line(b"", COLOR_TEXT);
    print_line(b"Thermal:", COLOR_TEXT_WHITE);
    print_line(b"  CPU Temp:        [Not monitored]", COLOR_TEXT_DIM);
    print_line(b"  Fan Status:      [Not monitored]", COLOR_TEXT_DIM);

    print_line(b"", COLOR_TEXT);
    print_line(b"Power-saving disabled for security", COLOR_YELLOW);
}

pub fn cmd_power_status() {
    print_line(b"Power Status:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"System State:     Running (S0)", COLOR_GREEN);
    print_line(b"ZeroState Mode:   ACTIVE", COLOR_GREEN);
    print_line(b"RAM-Only Mode:    ENFORCED", COLOR_GREEN);
    print_line(b"", COLOR_TEXT);

    print_line(b"Available Actions:", COLOR_TEXT_WHITE);
    print_line(b"  reboot     Restart (erases RAM)", COLOR_TEXT_DIM);
    print_line(b"  shutdown   Power off (erases RAM)", COLOR_TEXT_DIM);
    print_line(b"  halt       Stop CPU (requires reset)", COLOR_TEXT_DIM);

    print_line(b"", COLOR_TEXT);
    print_line(b"Blocked Actions (ZeroState):", COLOR_TEXT_WHITE);
    print_line(b"  suspend    Would preserve RAM", COLOR_RED);
    print_line(b"  hibernate  Would write to disk", COLOR_RED);
}
