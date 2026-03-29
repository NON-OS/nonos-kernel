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

use super::error::ParseError;
use crate::image_format::footer::ImageFooter;

pub fn validate_no_overlap(footer: &ImageFooter) -> Result<(), ParseError> {
    let k_start = footer.kernel_offset as u64;
    let k_end = footer.kernel_end().ok_or(ParseError::KernelOffsetOverflow)?;

    let s_start = footer.signature_offset as u64;
    let s_end = footer.signature_end().ok_or(ParseError::SignatureOffsetOverflow)?;

    if ranges_overlap(k_start, k_end, s_start, s_end) {
        return Err(ParseError::OverlappingRegions);
    }

    if footer.proof_size > 0 {
        let p_start = footer.proof_offset as u64;
        let p_end = footer.proof_end().ok_or(ParseError::ProofOffsetOverflow)?;

        if ranges_overlap(k_start, k_end, p_start, p_end) {
            return Err(ParseError::OverlappingRegions);
        }

        if ranges_overlap(s_start, s_end, p_start, p_end) {
            return Err(ParseError::OverlappingRegions);
        }
    }

    Ok(())
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}
