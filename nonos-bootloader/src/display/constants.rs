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

pub const COLOR_PRIMARY: u32 = 0xFF00D4AA;
pub const COLOR_SECONDARY: u32 = 0xFF1A3A3A;

pub const COLOR_BACKGROUND: u32 = 0xFF0D1117;
pub const COLOR_BOX_BG: u32 = 0xFF161B22;
pub const COLOR_PROGRESS_BG: u32 = 0xFF21262D;

pub const COLOR_BORDER: u32 = 0xFF30363D;
pub const COLOR_ACCENT: u32 = 0xFF00D4AA;
pub const COLOR_ACCENT_DIM: u32 = 0xFF007A63;

pub const COLOR_SUCCESS: u32 = 0xFF3FB950;
pub const COLOR_ERROR: u32 = 0xFFF85149;
pub const COLOR_WARNING: u32 = 0xFFD29922;

pub const COLOR_TEXT_PRIMARY: u32 = 0xFFF0F6FC;
pub const COLOR_TEXT_WHITE: u32 = 0xFFFFFFFF;
pub const COLOR_TEXT_DIM: u32 = 0xFF8B949E;
pub const COLOR_TEXT_MUTED: u32 = 0xFF484F58;

pub const COLOR_HASH_BYTE: u32 = 0xFF00D4AA;
pub const COLOR_CRYPTO_CYAN: u32 = 0xFF00D4AA;
pub const COLOR_ZK_PURPLE: u32 = 0xFFA371F7;

pub const COLOR_LOGO_PRIMARY: u32 = 0xFF00D4AA;
pub const COLOR_LOGO_SECONDARY: u32 = 0xFF1A3A3A;

pub const COLOR_GLASS_BG: u32 = 0xFF161B22;
pub const COLOR_GLASS_BORDER: u32 = 0xFF30363D;
pub const COLOR_ERROR_BG: u32 = 0xFF2D1B1B;

pub const LOGO_SIZE: u32 = 64;
pub const PROGRESS_BAR_WIDTH: u32 = 400;
pub const PROGRESS_BAR_HEIGHT: u32 = 4;
pub const HASH_BOX_WIDTH: u32 = 520;
pub const HASH_BOX_HEIGHT: u32 = 48;
pub const ZK_BOX_HEIGHT: u32 = 64;
pub const SIG_BOX_HEIGHT: u32 = 80;
pub const STATUS_BOX_WIDTH: u32 = 400;
pub const STATUS_BOX_HEIGHT: u32 = 24;

pub const PANEL_RADIUS: u32 = 8;
pub const PANEL_PADDING: u32 = 24;
pub const SECTION_GAP: u32 = 16;

pub const HASH_ANIMATION_FRAMES: u32 = 16;
pub const PROGRESS_ANIMATION_STEP: u32 = 2;

pub const STAGE_INIT: u8 = 0;
pub const STAGE_UEFI: u8 = 1;
pub const STAGE_SECURITY: u8 = 2;
pub const STAGE_HARDWARE: u8 = 3;
pub const STAGE_KERNEL_LOAD: u8 = 4;
pub const STAGE_BLAKE3_HASH: u8 = 5;
pub const STAGE_ED25519_VERIFY: u8 = 6;
pub const STAGE_ZK_VERIFY: u8 = 7;
pub const STAGE_ELF_PARSE: u8 = 8;
pub const STAGE_HANDOFF: u8 = 9;
pub const STAGE_COMPLETE: u8 = 10;
