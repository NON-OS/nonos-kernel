// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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

mod helpers;
mod corb_rirb;
mod stream;
mod codec;
mod init;
mod hda_controller;

// Re-export main controller
pub use hda_controller::HdAudioController;
// Re-export register access trait
pub use helpers::RegisterAccess;
// Re-export initialization types and functions
pub use init::{
    Capabilities, InitStage, init_stats,
    shutdown_controller, is_running, is_in_reset, read_version, validate_controller,
};

// Re-export codec types and functions
pub use codec::{
    CodecInfo, WidgetInfo, AudioPath, CodecPaths, CodecQuirks,
    vendor_name, device_name, get_codec_quirks, apply_codec_quirks, codec_stats,
    widget_type_name, pin_device_type_name,
};

// Re-export CORB/RIRB utilities
pub use corb_rirb::compose_verb;
