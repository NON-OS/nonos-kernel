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

#[derive(Debug, Clone, Copy)]
pub struct DmaConstraints {
    pub alignment: usize,
    pub max_segment_size: usize,
    pub dma32_only: bool,
    pub coherent: bool,
}

impl DmaConstraints {
    pub const fn new() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: true,
        }
    }

    pub const fn dma32() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: true,
            coherent: true,
        }
    }

    pub const fn non_coherent() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: false,
        }
    }
}
