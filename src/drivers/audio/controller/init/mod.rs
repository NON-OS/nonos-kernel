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

mod types;
mod reset;
mod capabilities;
mod discover;
mod controller;

pub(crate) use types::{InitStage, Capabilities};
pub(crate) use reset::reset_controller;
pub(crate) use capabilities::{read_capabilities, read_codec_mask, find_primary_codec};
pub(crate) use discover::{init_command_buffers, discover_codecs};
pub(crate) use controller::{init_controller, shutdown_controller, disable_interrupts, clear_codec_status,
    is_in_reset, is_running, read_version, validate_controller};
