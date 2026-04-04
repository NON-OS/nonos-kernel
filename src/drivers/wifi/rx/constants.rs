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

pub(super) const RX_BUFFER_SIZE: usize = 64;

pub(super) const FRAME_TYPE_MGMT: u8 = 0;
pub(super) const FRAME_TYPE_CTRL: u8 = 1;
pub(super) const FRAME_TYPE_DATA: u8 = 2;

pub(super) const MGMT_SUBTYPE_BEACON: u8 = 8;
pub(super) const MGMT_SUBTYPE_PROBE_RESP: u8 = 5;
pub(super) const MGMT_SUBTYPE_AUTH: u8 = 11;
pub(super) const MGMT_SUBTYPE_DEAUTH: u8 = 12;
pub(super) const MGMT_SUBTYPE_ASSOC_RESP: u8 = 1;
pub(super) const MGMT_SUBTYPE_DISASSOC: u8 = 10;

pub(super) const DATA_SUBTYPE_DATA: u8 = 0;
pub(super) const DATA_SUBTYPE_QOS_DATA: u8 = 8;
