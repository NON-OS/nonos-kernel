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

use super::super::super::types::{flags, BootHandoffV1};
use super::super::error::{FbGeometryReason, HandoffError};

pub(super) fn check(handoff: &BootHandoffV1) -> Result<(), HandoffError> {
    if !handoff.has_flag(flags::FB_AVAILABLE) {
        return Ok(());
    }
    let fb = &handoff.fb;
    if fb.width == 0 {
        return Err(reject(FbGeometryReason::ZeroWidth));
    }
    if fb.height == 0 {
        return Err(reject(FbGeometryReason::ZeroHeight));
    }
    if fb.stride == 0 {
        return Err(reject(FbGeometryReason::ZeroStride));
    }
    let row_bytes = (fb.width as u64) * (fb.bytes_per_pixel() as u64);
    if (fb.stride as u64) < row_bytes {
        return Err(reject(FbGeometryReason::StrideTooSmall));
    }
    let area = (fb.stride as u64) * (fb.height as u64);
    if area > fb.size {
        return Err(reject(FbGeometryReason::AreaOverflow));
    }
    Ok(())
}

fn reject(reason: FbGeometryReason) -> HandoffError {
    HandoffError::FramebufferGeometry { reason }
}
