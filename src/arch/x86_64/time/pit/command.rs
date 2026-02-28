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

pub(super) const MODE_0: u8 = 0x00;
pub(super) const MODE_1: u8 = 0x02;
pub(super) const MODE_2: u8 = 0x04;
pub(super) const MODE_3: u8 = 0x06;
pub(super) const MODE_4: u8 = 0x08;
pub(super) const MODE_5: u8 = 0x0A;

pub(super) const ACCESS_LATCH: u8 = 0x00;
pub(super) const ACCESS_LOBYTE: u8 = 0x10;
pub(super) const ACCESS_HIBYTE: u8 = 0x20;
pub(super) const ACCESS_LOHI: u8 = 0x30;

pub(super) const CHANNEL_0: u8 = 0x00;
pub(super) const CHANNEL_1: u8 = 0x40;
pub(super) const CHANNEL_2: u8 = 0x80;
pub(super) const READ_BACK: u8 = 0xC0;

pub(super) const READBACK_COUNT: u8 = 0x20;
pub(super) const READBACK_CH0: u8 = 0x02;
pub(super) const READBACK_CH1: u8 = 0x04;
pub(super) const READBACK_CH2: u8 = 0x08;
