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

use super::super::constants::*;
use super::super::error::{XhciError, XhciResult};
use super::region::DmaRegion;

pub struct DmaRegionBuilder {
    size: usize,
    alignment: usize,
    zero: bool,
    for_trb: bool,
}

impl DmaRegionBuilder {
    pub fn new(size: usize) -> Self {
        Self { size, alignment: DMA_MIN_ALIGNMENT, zero: true, for_trb: false }
    }
    pub fn alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment;
        self
    }
    pub fn for_trb(mut self) -> Self {
        self.for_trb = true;
        self.alignment = self.alignment.max(TRB_ALIGNMENT as usize);
        self
    }
    pub fn zero(mut self, zero: bool) -> Self {
        self.zero = zero;
        self
    }

    pub fn build(self) -> XhciResult<DmaRegion> {
        if self.for_trb && self.alignment < TRB_ALIGNMENT as usize {
            return Err(XhciError::TrbMisaligned(0));
        }
        DmaRegion::new_aligned(self.size, self.alignment, self.zero)
    }
}
