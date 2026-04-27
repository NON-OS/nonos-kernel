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

mod elan;
mod helpers;
mod hp;
mod offset;
mod precision;
mod standard;
mod synaptics;
mod windows;

pub(crate) use elan::try_parse_elan;
pub(crate) use helpers::{parse_buttons, parse_contact_point};
pub(crate) use hp::try_parse_hp_precision_touchpad;
pub(crate) use precision::try_parse_precision_touchpad;
pub(crate) use standard::try_parse_standard_touchpad;
pub(crate) use synaptics::try_parse_synaptics;
pub(crate) use windows::try_parse_windows_precision;
