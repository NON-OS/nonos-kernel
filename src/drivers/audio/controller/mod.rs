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

mod api;
pub mod codec;
mod corb_rirb;
mod hda_controller;
mod helpers;
mod init;
mod stream;

pub use api::{
    codec_statistics, describe_pin_device, describe_widget, find_audio_paths, get_codec_details,
    get_codec_device_name, get_codec_vendor_name,
};
pub use corb_rirb::compose_verb;
pub use hda_controller::HdAudioController;
pub use helpers::RegisterAccess;
pub use init::{
    is_in_reset, is_running, read_version, shutdown_controller, validate_controller, Capabilities,
    InitStage,
};
