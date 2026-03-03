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

use super::super::constants::KERNEL_PHYS_MASK;
use super::super::constants::KERNEL_RESERVED_SIZE;
use super::super::error::WifiError;
use crate::memory::layout::KERNEL_BASE;
use x86_64::PhysAddr;

pub(crate) const MAX_DMA_PHYS_ADDR: u64 = 0x1_0000_0000_0000;

pub(crate) fn validate_dma_phys_addr(addr: PhysAddr) -> Result<(), WifiError> {
    let raw = addr.as_u64();
    if raw == 0 {
        return Err(WifiError::InvalidParameter);
    }
    if raw >= MAX_DMA_PHYS_ADDR {
        return Err(WifiError::DmaError);
    }
    let kernel_phys_base = KERNEL_BASE as u64 & KERNEL_PHYS_MASK;
    if raw >= kernel_phys_base && raw < kernel_phys_base + KERNEL_RESERVED_SIZE {
        return Err(WifiError::DmaError);
    }
    Ok(())
}

#[repr(C, align(256))]
pub(crate) struct TxFrameDescriptor {
    pub tb: [TransferBuffer; 20],
    pub num_tbs: u32,
    _pad: [u8; 12],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct TransferBuffer {
    pub lo: u32,
    pub hi_n_len: u32,
}

impl TransferBuffer {
    pub(crate) fn new(addr: PhysAddr, len: u16) -> Self {
        Self {
            lo: addr.as_u64() as u32,
            hi_n_len: ((addr.as_u64() >> 32) as u32 & 0xFF) | ((len as u32) << 16),
        }
    }
}

impl Default for TxFrameDescriptor {
    fn default() -> Self {
        Self {
            tb: [TransferBuffer::default(); 20],
            num_tbs: 0,
            _pad: [0; 12],
        }
    }
}
