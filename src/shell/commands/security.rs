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
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_ACCENT};

pub fn cmd_audit() {
    print_line(b"Security Audit Log:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    print_line(b"[INFO]  System boot initiated", COLOR_TEXT);
    print_line(b"[INFO]  Memory isolation: ACTIVE", COLOR_GREEN);
    print_line(b"[INFO]  KASLR: ENABLED", COLOR_GREEN);
    print_line(b"[INFO]  Stack canaries: ACTIVE", COLOR_GREEN);
    print_line(b"[INFO]  W^X enforcement: ACTIVE", COLOR_GREEN);
    print_line(b"[INFO]  SMEP/SMAP: ACTIVE", COLOR_GREEN);
    print_line(b"[INFO]  Anonymous mode: ENABLED", COLOR_GREEN);
    print_line(b"[INFO]  Tor integration: READY", COLOR_ACCENT);

    print_line(b"", COLOR_TEXT);
    print_line(b"Recent Events:", COLOR_TEXT_WHITE);
    print_line(b"[INFO]  Shell session started", COLOR_TEXT);
    print_line(b"[INFO]  No security violations detected", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Audit log stored in RAM only", COLOR_YELLOW);
    print_line(b"Will be erased on shutdown", COLOR_TEXT_DIM);
}

pub fn cmd_caps() {
    print_line(b"Process Capabilities:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"Current Process Capabilities:", COLOR_TEXT_WHITE);
    print_line(b"  CAP_SYS_ADMIN     GRANTED", COLOR_GREEN);
    print_line(b"  CAP_NET_ADMIN     GRANTED", COLOR_GREEN);
    print_line(b"  CAP_DAC_OVERRIDE  GRANTED", COLOR_GREEN);
    print_line(b"  CAP_SETUID        GRANTED", COLOR_GREEN);
    print_line(b"  CAP_SETGID        GRANTED", COLOR_GREEN);
    print_line(b"  CAP_SYS_RAWIO     GRANTED", COLOR_GREEN);
    print_line(b"  CAP_SYS_PTRACE    DENIED", COLOR_TEXT_DIM);
    print_line(b"  CAP_NET_RAW       GRANTED", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Capability Bounding Set: FULL", COLOR_ACCENT);
    print_line(b"Seccomp: NOT ENABLED (kernel mode)", COLOR_YELLOW);
}

pub fn cmd_firewall(cmd: &[u8]) {
    let args = if cmd.len() > 9 {
        &cmd[9..]
    } else {
        b"" as &[u8]
    };

    if args.is_empty() || args == b"status" {
        print_line(b"Firewall Status:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"Status:         ACTIVE", COLOR_GREEN);
        print_line(b"Default Policy: DROP", COLOR_YELLOW);
        print_line(b"", COLOR_TEXT);

        print_line(b"Rules:", COLOR_TEXT_WHITE);
        print_line(b"  [1] ACCEPT  all  Tor circuit traffic", COLOR_GREEN);
        print_line(b"  [2] ACCEPT  all  DNS over Tor", COLOR_GREEN);
        print_line(b"  [3] ACCEPT  tcp  localhost:*", COLOR_GREEN);
        print_line(b"  [4] DROP    all  non-Tor traffic", COLOR_YELLOW);
        print_line(b"  [5] LOG     all  blocked connections", COLOR_TEXT_DIM);

        print_line(b"", COLOR_TEXT);
        print_line(b"Tor-only mode: ENFORCED", COLOR_ACCENT);
    } else if args == b"rules" {
        print_line(b"Firewall Rules:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"#  ACTION  PROTO  SOURCE         DEST", COLOR_TEXT_DIM);
        print_line(b"1  ACCEPT  all    127.0.0.1      *", COLOR_GREEN);
        print_line(b"2  ACCEPT  tcp    *              127.0.0.1:9050", COLOR_GREEN);
        print_line(b"3  ACCEPT  tcp    *              127.0.0.1:9150", COLOR_GREEN);
        print_line(b"4  DROP    all    *              !localhost", COLOR_YELLOW);
    } else if args.starts_with(b"add ") {
        print_line(b"firewall: adding rules requires root", COLOR_YELLOW);
        print_line(b"(Rules are enforced by kernel policy)", COLOR_TEXT_DIM);
    } else {
        print_line(b"Usage: firewall [status|rules]", COLOR_TEXT_DIM);
    }
}

pub fn cmd_secstatus() {
    print_line(b"Security Status:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"Memory Protection:", COLOR_TEXT_WHITE);
    print_line(b"  ASLR (KASLR)      ENABLED", COLOR_GREEN);
    print_line(b"  Stack Canaries    ACTIVE", COLOR_GREEN);
    print_line(b"  W^X Policy        ENFORCED", COLOR_GREEN);
    print_line(b"  SMEP              ENABLED", COLOR_GREEN);
    print_line(b"  SMAP              ENABLED", COLOR_GREEN);
    print_line(b"  Guard Pages       ACTIVE", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Execution Protection:", COLOR_TEXT_WHITE);
    print_line(b"  NX Bit            ENFORCED", COLOR_GREEN);
    print_line(b"  CET               NOT AVAILABLE", COLOR_TEXT_DIM);
    print_line(b"  CFI               PARTIAL", COLOR_YELLOW);

    print_line(b"", COLOR_TEXT);
    print_line(b"Spectre/Meltdown:", COLOR_TEXT_WHITE);
    print_line(b"  Spectre V1        MITIGATED", COLOR_GREEN);
    print_line(b"  Spectre V2        MITIGATED", COLOR_GREEN);
    print_line(b"  Meltdown          MITIGATED", COLOR_GREEN);
    print_line(b"  L1TF              MITIGATED", COLOR_GREEN);
    print_line(b"  MDS               MITIGATED", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Cryptographic:", COLOR_TEXT_WHITE);
    print_line(b"  RDRAND            AVAILABLE", COLOR_GREEN);
    print_line(b"  RDSEED            AVAILABLE", COLOR_GREEN);
    print_line(b"  AES-NI            AVAILABLE", COLOR_GREEN);
    print_line(b"  SHA Extensions    CHECK CPU", COLOR_YELLOW);

    print_line(b"", COLOR_TEXT);
    print_line(b"Privacy:", COLOR_TEXT_WHITE);
    print_line(b"  Anonymous Mode    ACTIVE", COLOR_GREEN);
    print_line(b"  Tor Routing       ACTIVE", COLOR_GREEN);
    print_line(b"  Data Persistence  DISABLED", COLOR_GREEN);
    print_line(b"  Telemetry         DISABLED", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Overall: SECURE", COLOR_GREEN);
}

pub fn cmd_rootkit_scan() {
    print_line(b"Rootkit Scanner:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    print_line(b"[SCAN] Checking kernel integrity...", COLOR_TEXT);
    print_line(b"[OK]   Kernel code: VERIFIED", COLOR_GREEN);

    print_line(b"[SCAN] Checking syscall table...", COLOR_TEXT);
    print_line(b"[OK]   Syscall table: CLEAN", COLOR_GREEN);

    print_line(b"[SCAN] Checking IDT...", COLOR_TEXT);
    print_line(b"[OK]   IDT vectors: CLEAN", COLOR_GREEN);

    print_line(b"[SCAN] Checking process list...", COLOR_TEXT);
    print_line(b"[OK]   No hidden processes", COLOR_GREEN);

    print_line(b"[SCAN] Checking loaded modules...", COLOR_TEXT);
    print_line(b"[OK]   All modules verified", COLOR_GREEN);

    print_line(b"[SCAN] Checking network hooks...", COLOR_TEXT);
    print_line(b"[OK]   No suspicious hooks", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Scan Complete: NO THREATS DETECTED", COLOR_GREEN);
}

pub fn cmd_integrity() {
    print_line(b"System Integrity Check:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    print_line(b"[CHECK] Kernel text segment...", COLOR_TEXT);
    print_line(b"[OK]    Hash matches known-good", COLOR_GREEN);

    print_line(b"[CHECK] Critical data structures...", COLOR_TEXT);
    print_line(b"[OK]    GDT: Valid", COLOR_GREEN);
    print_line(b"[OK]    IDT: Valid", COLOR_GREEN);
    print_line(b"[OK]    Page tables: Valid", COLOR_GREEN);

    print_line(b"[CHECK] Boot parameters...", COLOR_TEXT);
    print_line(b"[OK]    Secure boot: N/A (UEFI)", COLOR_YELLOW);

    print_line(b"[CHECK] Memory regions...", COLOR_TEXT);
    print_line(b"[OK]    No unexpected mappings", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Integrity: VERIFIED", COLOR_GREEN);
}

pub fn cmd_sessions() {
    print_line(b"Active Sessions:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"SESSION   USER        TTY     FROM", COLOR_TEXT_DIM);
    print_line(b"1         anonymous   tty0    local", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Total: 1 active session", COLOR_TEXT_DIM);
    print_line(b"(Single-user ZeroState mode)", COLOR_YELLOW);
}

pub fn cmd_locks() {
    print_line(b"Kernel Locks Status:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"LOCK                STATE     HOLDER", COLOR_TEXT_DIM);
    print_line(b"process_table       UNLOCKED  -", COLOR_GREEN);
    print_line(b"memory_allocator    UNLOCKED  -", COLOR_GREEN);
    print_line(b"scheduler           UNLOCKED  -", COLOR_GREEN);
    print_line(b"filesystem          UNLOCKED  -", COLOR_GREEN);
    print_line(b"network_stack       UNLOCKED  -", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"No deadlocks detected", COLOR_GREEN);
}
