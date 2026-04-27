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

use crate::graphics::framebuffer::fill_rounded_rect;
use crate::graphics::window::settings::render::{draw_string, draw_toggle};
use crate::sys::settings::api::kernel as ks;

const BG: u32 = 0xFF161B22;
const TEXT: u32 = 0xFFE6EDF3;
const DIM: u32 = 0xFF7D8590;
const WARN: u32 = 0xFFF59E0B;
const OK: u32 = 0xFF10B981;

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    fill_rounded_rect(x + 16, y, w - 32, 160, 8, BG);
    draw_string(x + 28, y + 12, b"CPU Security", TEXT);
    draw_row(x, y + 32, w, b"ASLR", b"Randomize memory layout", ks::kernel_aslr());
    draw_row(x, y + 56, w, b"Stack Guard", b"Protect against overflow", ks::kernel_stack_guard());
    draw_row(x, y + 80, w, b"NX Bit", b"No-execute protection", ks::kernel_nx_bit());
    draw_row(x, y + 104, w, b"SMEP", b"Supervisor exec prevention", ks::kernel_smep());
    draw_row(x, y + 128, w, b"SMAP", b"Supervisor access prevention", ks::kernel_smap());
    fill_rounded_rect(x + 16, y + 170, w - 32, 110, 8, BG);
    draw_string(x + 28, y + 182, b"Kernel Features", TEXT);
    draw_row(x, y + 202, w, b"Preemption", b"Preemptive multitasking", ks::kernel_preempt());
    draw_row(x, y + 226, w, b"Huge Pages", b"2MB/1GB page support", ks::kernel_hugepages());
    draw_row(x, y + 250, w, b"IOMMU/VT-d", b"Device memory isolation", ks::kernel_iommu());
    fill_rounded_rect(x + 16, y + 290, w - 32, 110, 8, BG);
    draw_string(x + 28, y + 302, b"Debug & Diagnostics", TEXT);
    draw_row(x, y + 322, w, b"Debug Mode", b"Verbose kernel logging", ks::kernel_debug());
    draw_row(x, y + 346, w, b"Serial Console", b"Output to COM1", ks::kernel_serial());
    draw_row(x, y + 370, w, b"Watchdog", b"Hardware timeout reset", ks::kernel_watchdog());
    fill_rounded_rect(x + 16, y + 410, w - 32, 60, 8, BG);
    draw_string(x + 28, y + 422, b"Sandbox", TEXT);
    draw_row(x, y + 442, w, b"Seccomp", b"System call filtering", ks::kernel_seccomp());
    draw_status(x, y + 480, w);
}

fn draw_row(x: u32, y: u32, w: u32, label: &[u8], desc: &[u8], enabled: bool) {
    draw_string(x + 28, y, label, TEXT);
    draw_string(x + 120, y, desc, DIM);
    draw_toggle(x + w - 80, y - 4, enabled);
}

fn draw_status(x: u32, y: u32, w: u32) {
    fill_rounded_rect(x + 16, y, w - 32, 50, 8, BG);
    draw_string(x + 28, y + 12, b"Kernel Status", TEXT);
    let mut buf = [0u8; 32];
    buf[0..7].copy_from_slice(b"Uptime:");
    let uptime = crate::sys::clock::uptime_seconds();
    let hrs = uptime / 3600;
    let mins = (uptime % 3600) / 60;
    let secs = uptime % 60;
    buf[8] = b'0' + (hrs / 10) as u8;
    buf[9] = b'0' + (hrs % 10) as u8;
    buf[10] = b':';
    buf[11] = b'0' + (mins / 10) as u8;
    buf[12] = b'0' + (mins % 10) as u8;
    buf[13] = b':';
    buf[14] = b'0' + (secs / 10) as u8;
    buf[15] = b'0' + (secs % 10) as u8;
    draw_string(x + 28, y + 30, &buf[..16], OK);
    let mem = crate::memory::stats::used_mb();
    let mut mbuf = [0u8; 16];
    mbuf[0..4].copy_from_slice(b"RAM:");
    mbuf[5] = b'0' + (mem / 100) as u8;
    mbuf[6] = b'0' + ((mem / 10) % 10) as u8;
    mbuf[7] = b'0' + (mem % 10) as u8;
    mbuf[8..11].copy_from_slice(b" MB");
    draw_string(x + 180, y + 30, &mbuf[..11], WARN);
}
