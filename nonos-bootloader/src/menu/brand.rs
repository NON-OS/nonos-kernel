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

pub const ACCENT_PRIMARY: u32 = 0xFF66FFFF;
pub const ACCENT_SECONDARY: u32 = 0xFF2E5C5C;
pub const BG_PRIMARY: u32 = 0xFF000000;
pub const BG_SECONDARY: u32 = 0xFF0A0A0A;
pub const BG_CARD: u32 = 0xFF121212;
pub const BORDER: u32 = 0xFF1A1A1A;
pub const TEXT_PRIMARY: u32 = 0xFFE6EDF3;
pub const TEXT_SECONDARY: u32 = 0xFF9CA3AF;
pub const TEXT_MUTED: u32 = 0xFF6B7280;
pub const STATUS_OK: u32 = 0xFF10B981;
pub const STATUS_WARN: u32 = 0xFFF59E0B;
pub const STATUS_ERROR: u32 = 0xFFEF4444;

pub const LOGO: &[&[u8]] = &[
    b"  _   _  ___  _   _  ___  ____  ",
    b" | \\ | |/ _ \\| \\ | |/ _ \\/ ___| ",
    b" |  \\| | | | |  \\| | | | \\___ \\ ",
    b" | |\\  | |_| | |\\  | |_| |___) |",
    b" |_| \\_|\\___/|_| \\_|\\___/|____/ ",
];

pub const TAGLINE: &[u8] = b"SOVEREIGNTY FROM ZERO";
pub const VERSION: &[u8] = b"Bootloader v1.0.0";
