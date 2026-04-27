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

mod alphanumeric;
mod data;
mod error_correction;
mod format;
mod mask;
mod patterns;
mod types;

use alphanumeric::encode_alphanumeric;
use data::place_data;
use error_correction::add_error_correction;
use format::place_format_info;
use mask::apply_mask;
use patterns::{place_alignment_pattern, place_finder_patterns, place_timing_patterns};
pub(super) use types::QrCode;

pub fn encode_qr(data: &[u8]) -> Option<QrCode> {
    if data.len() > 47 {
        return None;
    }
    let mut qr = QrCode::new();
    place_finder_patterns(&mut qr);
    place_timing_patterns(&mut qr);
    place_alignment_pattern(&mut qr);
    let encoded = encode_alphanumeric(data)?;
    let with_ec = add_error_correction(&encoded);
    place_data(&mut qr, &with_ec);
    apply_mask(&mut qr, 2);
    place_format_info(&mut qr);
    Some(qr)
}
