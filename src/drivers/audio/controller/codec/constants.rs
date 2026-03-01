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

pub(super) const WIDGET_TYPE_DAC: u8 = 0x0;
pub(super) const WIDGET_TYPE_ADC: u8 = 0x1;
pub(super) const WIDGET_TYPE_MIXER: u8 = 0x2;
pub(super) const WIDGET_TYPE_SELECTOR: u8 = 0x3;
pub(super) const WIDGET_TYPE_PIN: u8 = 0x4;
pub(super) const WIDGET_TYPE_POWER: u8 = 0x5;
pub(super) const WIDGET_TYPE_VOLUME_KNOB: u8 = 0x6;
pub(super) const WIDGET_TYPE_BEEP: u8 = 0x7;

pub(super) const PIN_DEV_LINE_OUT: u8 = 0x0;
pub(super) const PIN_DEV_SPEAKER: u8 = 0x1;
pub(super) const PIN_DEV_HP_OUT: u8 = 0x2;
pub(super) const PIN_DEV_CD: u8 = 0x3;
pub(super) const PIN_DEV_SPDIF_OUT: u8 = 0x4;
pub(super) const PIN_DEV_DIG_OTHER_OUT: u8 = 0x5;
pub(super) const PIN_DEV_MODEM_LINE: u8 = 0x6;
pub(super) const PIN_DEV_MODEM_HANDSET: u8 = 0x7;
pub(super) const PIN_DEV_LINE_IN: u8 = 0x8;
pub(super) const PIN_DEV_AUX: u8 = 0x9;
pub(super) const PIN_DEV_MIC_IN: u8 = 0xA;
pub(super) const PIN_DEV_TELEPHONY: u8 = 0xB;
pub(super) const PIN_DEV_SPDIF_IN: u8 = 0xC;
pub(super) const PIN_DEV_DIG_OTHER_IN: u8 = 0xD;
pub(super) const PIN_DEV_OTHER: u8 = 0xF;

pub(super) const POWER_STATE_D0: u8 = 0x00;
pub(super) const PIN_CTL_OUT_EN: u8 = 0x40;
pub(super) const PIN_CTL_HP_EN: u8 = 0x80;
pub(super) const EAPD_ENABLE: u8 = 0x02;

pub(super) const MAX_OUTPUT_PATHS: usize = 8;
pub(super) const MAX_WIDGETS: usize = 64;
pub(super) const MAX_DEPTH: usize = 16;

pub(super) const PARAM_GPIO_COUNT: u16 = 0x11;
pub(super) const VERB_SET_GPIO_MASK: u16 = 0x716;
pub(super) const VERB_SET_GPIO_DIRECTION: u16 = 0x717;
pub(super) const VERB_SET_GPIO_DATA: u16 = 0x715;
