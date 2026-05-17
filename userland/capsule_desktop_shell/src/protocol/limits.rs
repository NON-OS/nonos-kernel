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

pub const TRAY_LABEL_MAX: usize = 24;
pub const NOTIFY_BODY_MAX: usize = 128;

// tray_id u32, label_len u32, label_bytes[24]
pub const TRAY_REGISTER_REQ_LEN: usize = 8 + TRAY_LABEL_MAX;
pub const TRAY_UPDATE_REQ_LEN: usize = 8 + TRAY_LABEL_MAX;

// tray_id u32, _pad u32
pub const TRAY_REMOVE_REQ_LEN: usize = 8;

// level u32, body_len u32, body_bytes[128]
pub const NOTIFY_REQ_LEN: usize = 8 + NOTIFY_BODY_MAX;
