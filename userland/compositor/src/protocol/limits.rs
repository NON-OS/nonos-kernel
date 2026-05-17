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

// SCENE_SUBMIT body: surface_handle u64, x u32, y u32, w u32, h u32, z u32, _pad u32
pub const SCENE_SUBMIT_REQ_LEN: usize = 32;

// DAMAGE_COMMIT body: x u32, y u32, w u32, h u32
pub const DAMAGE_COMMIT_REQ_LEN: usize = 16;

// FOCUS_SET body: target_pid u32, _pad u32
pub const FOCUS_SET_REQ_LEN: usize = 8;

// CURSOR_UPDATE body: x u32, y u32, visible u32, _pad u32
pub const CURSOR_UPDATE_REQ_LEN: usize = 16;

// SCENE_REMOVE body: owner_pid u32, _pad u32
pub const SCENE_REMOVE_REQ_LEN: usize = 8;
