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

use crate::memory::layout;

pub const DMA_VADDR_BASE: u64 = layout::DMA_BASE;
pub const DMA_VADDR_SIZE: u64 = layout::DMA_SIZE;
pub const DMA_VADDR_END: u64 = DMA_VADDR_BASE + DMA_VADDR_SIZE;

pub const PTE_DMA_COHERENT: u64 = 0x03;
pub const PTE_CACHE_DISABLE: u64 = 0x10;
pub const PTE_DMA_NON_COHERENT: u64 = PTE_DMA_COHERENT | PTE_CACHE_DISABLE;

pub const DEFAULT_POOL_REGION_SIZE: usize = layout::PAGE_SIZE;
pub const MAX_POOL_CAPACITY: usize = 1024;
