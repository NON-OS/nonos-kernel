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

#[derive(Clone, Copy, Debug)]
pub struct LayoutConfig {
    pub slide: u64,
    pub heap_lo: u64,
    pub heap_sz: u64,
    pub vm_lo: u64,
    pub vm_sz: u64,
    pub mmio_lo: u64,
    pub mmio_sz: u64,
    pub initialized: bool,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            slide: 0,
            heap_lo: KHEAP_BASE,
            heap_sz: KHEAP_SIZE,
            vm_lo: KVM_BASE,
            vm_sz: KVM_SIZE,
            mmio_lo: MMIO_BASE,
            mmio_sz: MMIO_SIZE,
            initialized: false,
        }
    }
}
