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

use super::grayscale::decode_grayscale;
use super::markers::parse_markers;
use super::ycbcr::decode_ycbcr;
use crate::apps::ecosystem::browser::engine::ImageData;

pub fn decode_jpeg(data: &[u8]) -> Option<ImageData> {
    let markers = parse_markers(data)?;
    if !markers.sof.is_baseline {
        return None;
    }
    let width = markers.sof.width;
    let height = markers.sof.height;
    let num_components = markers.sof.components.len();
    if num_components == 1 {
        decode_grayscale(data, &markers, width, height)
    } else if num_components == 3 {
        decode_ycbcr(data, &markers, width, height)
    } else {
        None
    }
}
