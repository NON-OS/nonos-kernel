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
pub const CONTROLLER_INFO_LEN: usize = 40;
pub const DISPLAY_INFO_LEN: usize = 12;
pub const CONTROLQ_STATE_LEN: usize = 24;

// Op payload lengths (compositor side).
pub const CREATE_RESOURCE_REQ_LEN: usize = 16; // resource_id u32, fmt u32, w u32, h u32
pub const ATTACH_BACKING_REQ_LEN: usize = 24; // res_id u32, _pad u32, addr u64, len u64
pub const TRANSFER_TO_HOST_REQ_LEN: usize = 32; // res_id u32, x u32, y u32, w u32, h u32, _pad u32, offset u64
pub const SET_SCANOUT_REQ_LEN: usize = 24; // scanout u32, res_id u32, x u32, y u32, w u32, h u32
pub const FLUSH_REQ_LEN: usize = 20; // res_id u32, x u32, y u32, w u32, h u32
pub const QUERY_CAPS_RESP_LEN: usize = 12; // num_scanouts u32, num_capsets u32, events_read u32

// MODE_LIST response: one mode entry per scanout slot.
//   le32 scanout_id, le32 enabled, le32 width, le32 height,
//   le32 x, le32 y, le32 current_resource_id, le32 _pad
pub const MODE_LIST_ENTRY_LEN: usize = 32;

// GET_PRIMARY_SURFACE response: handle + metadata for the driver-owned
// primary scanout buffer. Compositor attaches this through the
// kernel surface registry to write pixels directly into DMA-coherent
// pages the GPU reads on TRANSFER_TO_HOST.
//   le64 surface_handle, le32 resource_id, le32 width, le32 height,
//   le32 stride, le32 format, le32 _pad
pub const GET_PRIMARY_SURFACE_RESP_LEN: usize = 32;

pub const MAX_RESOURCES: usize = 64;
