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

pub(crate) use control::{set_mute, set_volume};
pub(crate) use discovery::{discover_codec, discover_paths};
pub use names::{device_name, pin_device_type_name, vendor_name, widget_type_name};
pub(crate) use path::{apply_codec_quirks, init_codec_path};
pub use quirks::{get_codec_quirks, CodecQuirks};
pub(crate) use stats::codec_stats;
pub use types::{AudioPath, CodecInfo, CodecPaths, WidgetInfo};

#[cfg(test)]
pub use stats::reset_codec_stats;
