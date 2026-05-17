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

pub const IPC_PAYLOAD_MAX: usize = 256;
pub const STATUS_LEN: usize = 4;

// argb u32, _pad u32
pub const SET_WALLPAPER_REQ_LEN: usize = 8;

// policy u32, _pad u32
pub const SET_POLICY_REQ_LEN: usize = 8;

// target_alpha u32, duration_ms u32
pub const FADE_REQ_LEN: usize = 8;

// argb u32, policy u32, width u32, height u32, alpha u32, _pad u32
pub const GET_WALLPAPER_RESP_LEN: usize = 24;
