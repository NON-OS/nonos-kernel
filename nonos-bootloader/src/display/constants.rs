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

pub const COLOR_PRIMARY: u32 = 0xFF66FFFF;
pub const COLOR_SECONDARY: u32 = 0xFF1A3333;

pub const COLOR_BACKGROUND: u32 = 0xFF000000;
pub const COLOR_BOX_BG: u32 = 0xFF0A0A0A;
pub const COLOR_PROGRESS_BG: u32 = 0xFF111111;

pub const COLOR_BORDER: u32 = 0xFF1A3333;
pub const COLOR_ACCENT: u32 = 0xFF00FF66;

pub const COLOR_SUCCESS: u32 = 0xFF00FF00;
pub const COLOR_ERROR: u32 = 0xFFFF0000;
pub const COLOR_WARNING: u32 = 0xFFFF8800;

pub const COLOR_TEXT_PRIMARY: u32 = 0xFF00FF66;
pub const COLOR_TEXT_WHITE: u32 = 0xFFFFFFFF;
pub const COLOR_TEXT_DIM: u32 = 0xFF336633;

pub const COLOR_HASH_BYTE: u32 = 0xFF00FFAA;
pub const COLOR_CRYPTO_CYAN: u32 = 0xFF00CCCC;
pub const COLOR_ZK_PURPLE: u32 = 0xFFAA00FF;

pub const COLOR_LOGO_PRIMARY: u32 = 0xFF66FFFF;
pub const COLOR_LOGO_SECONDARY: u32 = 0xFF1A3333;

pub const LOGO_SIZE: u32 = 64;
pub const PROGRESS_BAR_WIDTH: u32 = 300;
pub const PROGRESS_BAR_HEIGHT: u32 = 6;
pub const HASH_BOX_WIDTH: u32 = 460;
pub const HASH_BOX_HEIGHT: u32 = 54;
pub const ZK_BOX_HEIGHT: u32 = 70;
pub const SIG_BOX_HEIGHT: u32 = 84;
pub const STATUS_BOX_WIDTH: u32 = 360;
pub const STATUS_BOX_HEIGHT: u32 = 22;

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
