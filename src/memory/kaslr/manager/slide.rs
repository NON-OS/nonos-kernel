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

use super::super::error::{KaslrError, KaslrResult};
use super::super::types::Policy;
use crate::memory::layout;

pub(super) fn choose_slide(entropy: u64, policy: Policy) -> KaslrResult<u64> {
    if policy.min_slide >= policy.max_slide {
        return Err(KaslrError::InvalidPolicy);
    }

    let range = policy.max_slide - policy.min_slide;
    let granularity = if policy.align == 0 { layout::PAGE_SIZE as u64 } else { policy.align };

    if granularity == 0 {
        return Err(KaslrError::InvalidAlignment);
    }

    let aligned_range = (range / granularity) * granularity;
    if aligned_range == 0 {
        return Err(KaslrError::RangeTooSmall);
    }

    let slide_offset = entropy % aligned_range;
    let aligned_offset = (slide_offset / granularity) * granularity;
    let slide = policy.min_slide + aligned_offset;

    if slide < policy.min_slide || slide >= policy.max_slide {
        return Err(KaslrError::SlideOutOfRange);
    }
    if slide % granularity != 0 {
        return Err(KaslrError::SlideNotAligned);
    }

    Ok(slide)
}
