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
use crate::mem::heap;
use crate::sys::timer;

use super::utils::format_num_simple;

pub fn cmd_help() {
    print_line(b"N\xd8NOS Shell Commands:", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);
    print_line(b"System:   info mem cpu ps df free uptime", COLOR_TEXT_DIM);
    print_line(b"          version hostname uname clear", COLOR_TEXT_DIM);
    print_line(b"Hardware: lspci lscpu lsblk lsusb dmesg", COLOR_TEXT_DIM);
    print_line(b"Process:  kill pgrep pkill nice pidof top", COLOR_TEXT_DIM);
    print_line(b"Network:  net ifconfig ip route ping dns", COLOR_TEXT_DIM);
    print_line(b"          netstat arp ss nslookup tor anon", COLOR_TEXT_DIM);
    print_line(b"Files:    ls pwd cat mkdir rm touch cp mv", COLOR_TEXT_DIM);
    print_line(b"          chmod ln stat file find grep du", COLOR_TEXT_DIM);
    print_line(b"Crypto:   hash random genkey crypto hmac", COLOR_TEXT_DIM);
    print_line(b"Security: audit caps firewall secstatus", COLOR_TEXT_DIM);
    print_line(b"          rootkit-scan integrity sessions", COLOR_TEXT_DIM);
    print_line(b"Vault:    vault vault-seal vault-unseal", COLOR_TEXT_DIM);
    print_line(b"          vault-derive vault-keys vault-*", COLOR_TEXT_DIM);
    print_line(b"Modules:  lsmod modinfo sysctl kver depmod", COLOR_TEXT_DIM);
    print_line(b"Apps:     apps browser files editor calc", COLOR_TEXT_DIM);
    print_line(b"Other:    neofetch logo capsules about", COLOR_TEXT_DIM);
    print_line(b"          reboot shutdown", COLOR_TEXT_DIM);
}

pub fn cmd_about() {
    print_line(b"", COLOR_TEXT);
    print_line(b"  N\xd8NOS - Zero State OS", COLOR_ACCENT);
    print_line(b"  =====================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"  Privacy-first operating system", COLOR_TEXT);
    print_line(b"  that runs entirely in RAM.", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"  * No persistent storage", COLOR_GREEN);
    print_line(b"  * No tracking or telemetry", COLOR_GREEN);
    print_line(b"  * Anonymous by default", COLOR_GREEN);
    print_line(b"  * Data wiped on shutdown", COLOR_GREEN);
    print_line(b"", COLOR_TEXT);
    print_line(b"  eK@n\xd8nos-tech.xyz", COLOR_TEXT_DIM);
}

pub fn cmd_vault() {
    print_line(b"Crypto Vault Status:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"Ed25519:     READY", COLOR_GREEN);
    print_line(b"BLAKE3:      READY", COLOR_GREEN);
    print_line(b"AES-256:     READY", COLOR_GREEN);
    print_line(b"Keys:        In-memory only", COLOR_YELLOW);
    print_line(b"", COLOR_TEXT);
    print_line(b"Keys destroyed on shutdown.", COLOR_GREEN);
}

pub fn cmd_capsules() {
    print_line(b"Installed Capsules:", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"NAME          VERSION  STATUS", COLOR_TEXT_DIM);
    print_line(b"core          1.0.0    active", COLOR_GREEN);
    print_line(b"shell         1.0.0    active", COLOR_GREEN);
    print_line(b"net           1.0.0    active", COLOR_GREEN);
    print_line(b"vault         1.0.0    active", COLOR_GREEN);
    print_line(b"graphics      1.0.0    active", COLOR_GREEN);
    print_line(b"", COLOR_TEXT);
    print_line(b"5 capsules loaded (sandbox mode)", COLOR_ACCENT);
}

pub fn cmd_neofetch() {
    print_line(b"", COLOR_TEXT);
    print_line(b"       _  _  ___  _  _  ___  ___", COLOR_ACCENT);
    print_line(b"      | \\| |/ _ \\| \\| |/ _ \\/ __|", COLOR_ACCENT);
    print_line(b"      | .` | (_) | .` | (_) \\__ \\", COLOR_ACCENT);
    print_line(b"      |_|\\_|\\___/|_|\\_|\\___/|___/", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);
    print_line(b"  anonymous@n\xd8nos-zerostate", COLOR_TEXT_WHITE);
    print_line(b"  -------------------------", COLOR_TEXT_DIM);
    print_line(b"  OS:      N\xd8NOS ZeroState", COLOR_TEXT);
    print_line(b"  Kernel:  1.0.0-production", COLOR_TEXT);
    print_line(b"  Shell:   nsh (N\xd8NOS Shell)", COLOR_TEXT);

    let (heap_used, _freed, _peak, heap_free) = heap::stats();
    let total_mb = (heap_used + heap_free) / (1024 * 1024);
    let mut mem_line = [0u8; 48];
    mem_line[..10].copy_from_slice(b"  Memory:  ");
    let len = format_num_simple(&mut mem_line[10..], total_mb);
    mem_line[10+len..10+len+12].copy_from_slice(b" MB (RAM-only)");
    print_line(&mem_line[..10+len+12], COLOR_TEXT);

    if timer::is_init() {
        let mut uptime_buf = [0u8; 8];
        timer::format_uptime(&mut uptime_buf);
        let mut up_line = [0u8; 32];
        up_line[..10].copy_from_slice(b"  Uptime:  ");
        up_line[10..18].copy_from_slice(&uptime_buf);
        print_line(&up_line[..18], COLOR_TEXT);
    }

    print_line(b"  Privacy: Anonymous Mode", COLOR_GREEN);
}

pub fn cmd_logo() {
    print_line(b"", COLOR_TEXT);
    print_line(b"    ***********************", COLOR_ACCENT);
    print_line(b"    *                     *", COLOR_ACCENT);
    print_line(b"    *       N\xd8NOS         *", COLOR_ACCENT);
    print_line(b"    *     Zero State      *", COLOR_ACCENT);
    print_line(b"    *                     *", COLOR_ACCENT);
    print_line(b"    *   Privacy First     *", COLOR_ACCENT);
    print_line(b"    *                     *", COLOR_ACCENT);
    print_line(b"    ***********************", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);
}
