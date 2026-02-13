// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::*;
use super::font::{draw_string, CHAR_HEIGHT};
use super::gop::{clear_screen, fill_rect, get_dimensions};
use super::ui::{draw_logo, draw_progress_bar, StageStatus};
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

static CURRENT_STAGE: AtomicU8 = AtomicU8::new(STAGE_INIT);
static ANIMATION_FRAME: AtomicU32 = AtomicU32::new(0);
static HASH_REVEAL: AtomicU32 = AtomicU32::new(0);

pub struct BootCryptoState {
    pub kernel_hash: [u8; 32],
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],
    pub signature_valid: Option<bool>,
    pub zk_present: bool,
    pub zk_verified: Option<bool>,
    pub zk_program_hash: [u8; 32],
}

impl BootCryptoState {
    pub const fn new() -> Self {
        Self {
            kernel_hash: [0u8; 32],
            signature_r: [0u8; 32],
            signature_s: [0u8; 32],
            signature_valid: None,
            zk_present: false,
            zk_verified: None,
            zk_program_hash: [0u8; 32],
        }
    }
}

const ASCII_BANNER: &[&[u8]] = &[
    b"",
    b" ##    ## ######  ##    ## ######  ######",
    b" ###   ## ##   ## ###   ## ##   ## ##    ",
    b" ## #  ## ##   ## ## #  ## ##   ## ##### ",
    b" ##  # ## ##   ## ##  # ## ##   ##     ##",
    b" ##   ### ##   ## ##   ### ##   ## ##  ##",
    b" ##    ## ######  ##    ## ######  ##### ",
    b"",
];

pub fn init_boot_screen() {
    clear_screen(COLOR_BACKGROUND);

    let (width, height) = get_dimensions();
    if width == 0 || height == 0 {
        return;
    }

    // Draw ASCII banner at top left
    let banner_x = 16u32;
    let mut banner_y = 12u32;

    for line in ASCII_BANNER {
        draw_string(banner_x, banner_y, line, COLOR_LOGO_PRIMARY);
        banner_y += CHAR_HEIGHT + 2;
    }

    // Subtitle below banner with proper spacing
    draw_string(
        banner_x + 4,
        banner_y + 8,
        b"ZeroState Bootloader v1.0",
        COLOR_ACCENT,
    );
    draw_string(
        banner_x + 4,
        banner_y + 28,
        b"Cryptographic Boot Verification",
        COLOR_TEXT_DIM,
    );

    // Separator line
    let sep_y = banner_y + 52;
    fill_rect(banner_x, sep_y, width / 2 - 40, 1, COLOR_TEXT_DIM);

    let right_panel_x = width / 2 + 60;
    draw_logo(right_panel_x + 40, 16);

    // OS name below logo
    draw_string(right_panel_x, 130, b"NONOS", COLOR_LOGO_PRIMARY);
    draw_string(right_panel_x, 148, b"ZeroState OS", COLOR_SECONDARY);

    // Boot verification section
    draw_string(right_panel_x, 180, b"Boot Verification:", COLOR_TEXT_DIM);

    CURRENT_STAGE.store(STAGE_INIT, Ordering::Release);
}

pub fn update_stage(stage: u8, status: StageStatus) {
    let (width, _) = get_dimensions();
    if width == 0 {
        return;
    }

    CURRENT_STAGE.store(stage, Ordering::Release);

    let right_x = width / 2 + 60;
    let stage_y_base = 200;

    let (stage_offset, label, detail) = match stage {
        STAGE_UEFI => (0, b"UEFI       ", b"SystemTable init"),
        STAGE_SECURITY => (1, b"Security   ", b"Policy enforce  "),
        STAGE_HARDWARE => (2, b"Hardware   ", b"ACPI/PCI enum   "),
        STAGE_KERNEL_LOAD => (3, b"Loader     ", b"kernel.bin read "),
        STAGE_BLAKE3_HASH => (4, b"BLAKE3     ", b"256-bit hash    "),
        STAGE_ED25519_VERIFY => (5, b"Ed25519    ", b"Signature verify"),
        STAGE_ZK_VERIFY => (6, b"Groth16    ", b"ZK attestation  "),
        STAGE_ELF_PARSE => (7, b"ELF        ", b"Segment mapping "),
        STAGE_HANDOFF => (8, b"Handoff    ", b"ExitBootServices"),
        STAGE_COMPLETE => (9, b"Complete   ", b"Kernel running  "),
        _ => return,
    };

    let y = stage_y_base + stage_offset * (CHAR_HEIGHT + 6);

    let (prefix, color) = match status {
        StageStatus::Pending => (b"[ ] ", COLOR_TEXT_DIM),
        StageStatus::Running => (b"[*] ", COLOR_WARNING),
        StageStatus::Success => (b"[+] ", COLOR_SUCCESS),
        StageStatus::Failed => (b"[X] ", COLOR_ERROR),
    };

    draw_string(right_x, y, prefix, color);
    draw_string(right_x + 32, y, label, color);
    draw_string(right_x + 120, y, detail, COLOR_TEXT_DIM);
}

pub fn show_crypto_verification(crypto: &BootCryptoState) {
    let (width, height) = get_dimensions();
    if width == 0 {
        return;
    }

    let right_x = width / 2 + 60;
    let crypto_y = height - 160;

    draw_string(right_x, crypto_y, b"Cryptographic State:", COLOR_TEXT_DIM);

    let mut hash_line = [0u8; 48];
    hash_line[..7].copy_from_slice(b"BLAKE3 ");
    format_hash_short(&crypto.kernel_hash, &mut hash_line[7..]);
    draw_string(right_x, crypto_y + 18, &hash_line, COLOR_SUCCESS);

    let sig_status = match crypto.signature_valid {
        Some(true) => (b"Ed25519 VALID              ", COLOR_SUCCESS),
        Some(false) => (b"Ed25519 INVALID            ", COLOR_ERROR),
        None => (b"Ed25519 pending...         ", COLOR_TEXT_DIM),
    };
    draw_string(right_x, crypto_y + 36, sig_status.0, sig_status.1);

    let zk_status = match (crypto.zk_present, crypto.zk_verified) {
        (true, Some(true)) => (b"ZK-SNARK VERIFIED          ", COLOR_SUCCESS),
        (true, Some(false)) => (b"ZK-SNARK FAILED            ", COLOR_ERROR),
        (true, None) => (b"ZK-SNARK verifying...      ", COLOR_WARNING),
        (false, _) => (b"ZK-SNARK not present       ", COLOR_TEXT_DIM),
    };
    draw_string(right_x, crypto_y + 54, zk_status.0, zk_status.1);

    if crypto.zk_present {
        let mut prog_line = [0u8; 48];
        prog_line[..8].copy_from_slice(b"Program ");
        format_hash_short(&crypto.zk_program_hash, &mut prog_line[8..]);
        draw_string(right_x, crypto_y + 72, &prog_line, COLOR_TEXT_DIM);
    }
}

fn format_hash_short(hash: &[u8], out: &mut [u8]) {
    let hex = b"0123456789abcdef";
    let show = hash.len().min(8);
    for (i, &b) in hash[..show].iter().enumerate() {
        if i * 2 + 1 < out.len() {
            out[i * 2] = hex[(b >> 4) as usize];
            out[i * 2 + 1] = hex[(b & 0xF) as usize];
        }
    }
    let pos = show * 2;
    if pos + 3 <= out.len() {
        out[pos] = b'.';
        out[pos + 1] = b'.';
        out[pos + 2] = b'.';
    }
}

pub fn animate_hash_reveal() {
    let current = HASH_REVEAL.load(Ordering::Relaxed);
    if current < 32 {
        HASH_REVEAL.store(current + 1, Ordering::Release);
    }
}

pub fn tick_animation() {
    let _ = ANIMATION_FRAME.fetch_add(1, Ordering::Relaxed);
}

pub fn draw_boot_progress(progress: u32, total: u32) {
    let (width, height) = get_dimensions();
    if width == 0 {
        return;
    }

    let bar_width = width / 2 - 60;
    let bar_x = 20;
    let bar_y = height - 24;

    draw_progress_bar(bar_x, bar_y, bar_width, 12, progress, total, COLOR_ACCENT);

    let percent = if total > 0 {
        (progress * 100) / total
    } else {
        0
    };
    let mut buf = [0u8; 8];
    let text = format_percent(percent, &mut buf);
    draw_string(bar_x + bar_width + 16, bar_y - 2, text, COLOR_TEXT_PRIMARY);
}

fn format_percent(percent: u32, buf: &mut [u8; 8]) -> &[u8] {
    let p = percent.min(100);
    buf[0] = b'[';
    if p >= 100 {
        buf[1] = b'1';
        buf[2] = b'0';
        buf[3] = b'0';
        buf[4] = b'%';
        buf[5] = b']';
        &buf[..6]
    } else if p >= 10 {
        buf[1] = b' ';
        buf[2] = b'0' + ((p / 10) as u8);
        buf[3] = b'0' + ((p % 10) as u8);
        buf[4] = b'%';
        buf[5] = b']';
        &buf[..6]
    } else {
        buf[1] = b' ';
        buf[2] = b' ';
        buf[3] = b'0' + (p as u8);
        buf[4] = b'%';
        buf[5] = b']';
        &buf[..6]
    }
}

pub fn show_handoff_message() {
    let (_, height) = get_dimensions();
    if height == 0 {
        return;
    }

    draw_string(
        20,
        height - 50,
        b">> Transferring to kernel...",
        COLOR_SUCCESS,
    );
}

pub fn show_error_screen(error: &[u8]) {
    let (width, height) = get_dimensions();
    if width == 0 {
        return;
    }

    fill_rect(0, height / 2 - 40, width, 80, COLOR_ERROR);
    draw_string(20, height / 2 - 30, b"BOOT FAILED", COLOR_TEXT_WHITE);
    draw_string(20, height / 2, error, COLOR_TEXT_WHITE);
}

pub fn reset_animation() {
    ANIMATION_FRAME.store(0, Ordering::Release);
    HASH_REVEAL.store(0, Ordering::Release);
}
