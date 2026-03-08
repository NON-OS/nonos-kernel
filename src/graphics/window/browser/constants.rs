// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

pub const MAX_URL_LEN: usize = 256;
pub const MAX_CONTENT_LINES: usize = 512;
pub const MAX_LINE_LEN: usize = 256;
pub const MAX_HISTORY: usize = 64;
pub const MAX_STATUS_LEN: usize = 64;
pub const MAX_TITLE_LEN: usize = 64;

pub const TOOLBAR_HEIGHT: u32 = 52;
pub const STATUS_BAR_HEIGHT: u32 = 28;
pub const BUTTON_WIDTH: u32 = 32;
pub const BUTTON_HEIGHT: u32 = 32;
pub const BUTTON_PADDING: u32 = 8;
pub const URL_BAR_PADDING: u32 = 8;
pub const CONTENT_PADDING: u32 = 16;

pub const COLOR_TOOLBAR_BG: u32 = 0xFF2C2C2E;
pub const COLOR_BUTTON_ACTIVE: u32 = 0xFF48484A;
pub const COLOR_BUTTON_INACTIVE: u32 = 0xFF3A3A3C;
pub const COLOR_URL_BAR_BG: u32 = 0xFF1C1C1E;
pub const COLOR_URL_BAR_BORDER: u32 = 0xFF48484A;
pub const COLOR_CONTENT_BG: u32 = 0xFF000000;
pub const COLOR_STATUS_BG: u32 = 0xFF1C1C1E;
pub const COLOR_SCROLLBAR_BG: u32 = 0xFF2C2C2E;
pub const COLOR_SCROLLBAR_THUMB: u32 = 0xFF636366;
pub const COLOR_STATUS_TEXT: u32 = 0xFF8E8E93;
pub const COLOR_DISABLED: u32 = 0xFF636366;

pub const GLASS_BG: u32 = 0xE82C2C2E;

pub const HTTP_TIMEOUT_MS: u64 = 20_000;
pub const MAX_RESPONSE_SIZE: usize = 5 * 1024 * 1024;
