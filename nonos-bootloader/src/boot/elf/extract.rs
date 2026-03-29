// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::prelude::*;

use crate::boot::util::fatal_reset;
use crate::image_format::{has_production_footer, parse_image_footer};
use crate::log::logger::log_error;

pub fn extract_kernel_payload<'a>(data: &'a [u8], st: &mut SystemTable<Boot>) -> &'a [u8] {
    if has_production_footer(data) {
        if let Ok(parsed) = parse_image_footer(data) {
            return parsed.kernel_bytes;
        }
    }

    log_error("elf", "Image missing production footer - refusing to parse");
    fatal_reset(st, "image missing production footer");
}
