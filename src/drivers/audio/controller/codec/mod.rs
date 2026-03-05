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

pub mod constants;
pub mod control;
pub mod discovery;
pub mod names;
pub mod path;
pub mod quirks;
pub mod stats;
pub mod types;

pub(crate) use control::{set_volume, set_mute};
pub(crate) use discovery::{discover_codec, discover_paths};
pub(crate) use names::{vendor_name, device_name, widget_type_name, pin_device_type_name};
pub(crate) use path::{init_codec_path, apply_codec_quirks};
pub(crate) use quirks::{CodecQuirks, get_codec_quirks};
pub(crate) use stats::codec_stats;
pub(crate) use types::{CodecInfo, WidgetInfo, AudioPath, CodecPaths};

#[cfg(test)]
pub use stats::reset_codec_stats;
