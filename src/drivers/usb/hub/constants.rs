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

pub const DT_HUB: u8 = 0x29;
pub const DT_SS_HUB: u8 = 0x2A;

pub const HUB_REQ_GET_STATUS: u8 = 0x00;
pub const HUB_REQ_CLEAR_FEATURE: u8 = 0x01;
pub const HUB_REQ_SET_FEATURE: u8 = 0x03;
pub const HUB_REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const HUB_REQ_SET_DESCRIPTOR: u8 = 0x07;
pub const HUB_REQ_CLEAR_TT_BUFFER: u8 = 0x08;
pub const HUB_REQ_RESET_TT: u8 = 0x09;
pub const HUB_REQ_GET_TT_STATE: u8 = 0x0A;
pub const HUB_REQ_STOP_TT: u8 = 0x0B;

pub const HUB_FEAT_C_HUB_LOCAL_POWER: u8 = 0;
pub const HUB_FEAT_C_HUB_OVER_CURRENT: u8 = 1;

pub const PORT_FEAT_CONNECTION: u8 = 0;
pub const PORT_FEAT_ENABLE: u8 = 1;
pub const PORT_FEAT_SUSPEND: u8 = 2;
pub const PORT_FEAT_OVER_CURRENT: u8 = 3;
pub const PORT_FEAT_RESET: u8 = 4;
pub const PORT_FEAT_POWER: u8 = 8;
pub const PORT_FEAT_LOWSPEED: u8 = 9;
pub const PORT_FEAT_C_CONNECTION: u8 = 16;
pub const PORT_FEAT_C_ENABLE: u8 = 17;
pub const PORT_FEAT_C_SUSPEND: u8 = 18;
pub const PORT_FEAT_C_OVER_CURRENT: u8 = 19;
pub const PORT_FEAT_C_RESET: u8 = 20;
pub const PORT_FEAT_TEST: u8 = 21;
pub const PORT_FEAT_INDICATOR: u8 = 22;
pub const PORT_FEAT_C_PORT_LINK_STATE: u8 = 25;
pub const PORT_FEAT_C_PORT_CONFIG_ERROR: u8 = 26;
pub const PORT_FEAT_PORT_REMOTE_WAKE_MASK: u8 = 27;
pub const PORT_FEAT_BH_PORT_RESET: u8 = 28;
pub const PORT_FEAT_C_BH_PORT_RESET: u8 = 29;
pub const PORT_FEAT_FORCE_LINKPM_ACCEPT: u8 = 30;

pub const PORT_STAT_CONNECTION: u16 = 1 << 0;
pub const PORT_STAT_ENABLE: u16 = 1 << 1;
pub const PORT_STAT_SUSPEND: u16 = 1 << 2;
pub const PORT_STAT_OVERCURRENT: u16 = 1 << 3;
pub const PORT_STAT_RESET: u16 = 1 << 4;
pub const PORT_STAT_POWER: u16 = 1 << 8;
pub const PORT_STAT_LOW_SPEED: u16 = 1 << 9;
pub const PORT_STAT_HIGH_SPEED: u16 = 1 << 10;
pub const PORT_STAT_TEST: u16 = 1 << 11;
pub const PORT_STAT_INDICATOR: u16 = 1 << 12;

pub const HUB_CHAR_LPSM_MASK: u16 = 0x0003;
pub const HUB_CHAR_COMPOUND: u16 = 0x0004;
pub const HUB_CHAR_OCPM_MASK: u16 = 0x0018;
pub const HUB_CHAR_TTTT_MASK: u16 = 0x0060;
pub const HUB_CHAR_PORTIND: u16 = 0x0080;

pub const MAX_HUB_PORTS: usize = 15;
pub const HUB_DEBOUNCE_MS: u32 = 100;
pub const HUB_RESET_MS: u32 = 50;
pub const HUB_POWER_ON_DELAY_MS: u32 = 100;

pub const FEAT_PORT_POWER: u16 = PORT_FEAT_POWER as u16;
pub const FEAT_PORT_RESET: u16 = PORT_FEAT_RESET as u16;
pub const FEAT_PORT_ENABLE: u16 = PORT_FEAT_ENABLE as u16;
pub const FEAT_C_PORT_CONNECTION: u16 = PORT_FEAT_C_CONNECTION as u16;
