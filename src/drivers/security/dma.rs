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

use super::constants::*;
use super::error::DriverError;
use x86_64::PhysAddr;

pub fn validate_dma_buffer(phys_addr: PhysAddr, size: usize) -> Result<(), DriverError> {
    let addr = phys_addr.as_u64();
    if size == 0 {
        return Err(DriverError::InvalidDmaBuffer);
    }

    if size > MAX_DMA_SIZE {
        return Err(DriverError::InvalidDmaBuffer);
    }

    let end = addr
        .checked_add(size as u64)
        .ok_or(DriverError::InvalidDmaBuffer)?;
    if end <= addr {
        return Err(DriverError::InvalidDmaBuffer);
    }

    if addr % PAGE_SIZE as u64 != 0 {
        return Err(DriverError::InvalidDmaBuffer);
    }

    if addr < KERNEL_PHYS_END {
        return Err(DriverError::InvalidDmaBuffer);
    }

    Ok(())
}

pub fn validate_prp_list(prp_list: &[u64], expected_size: usize) -> Result<(), DriverError> {
    if prp_list.is_empty() {
        return Err(DriverError::InvalidPrpList);
    }

    if prp_list.len() > MAX_PRP_ENTRIES {
        return Err(DriverError::InvalidPrpList);
    }

    let pages_needed = (expected_size + PAGE_SIZE - 1) / PAGE_SIZE;

    if prp_list.len() < pages_needed {
        return Err(DriverError::InvalidPrpList);
    }

    for (i, &prp) in prp_list.iter().enumerate() {
        if prp == 0 {
            return Err(DriverError::InvalidPrpList);
        }

        if i > 0 && (prp % PAGE_SIZE as u64 != 0) {
            return Err(DriverError::InvalidPrpList);
        }

        if prp < KERNEL_PHYS_END {
            return Err(DriverError::InvalidPrpList);
        }

        if prp > (1u64 << MAX_PHYS_ADDR_BITS) {
            return Err(DriverError::InvalidPrpList);
        }
    }

    Ok(())
}

pub fn validate_sg_list(sg_list: &[(u64, usize)], max_entries: usize) -> Result<usize, DriverError> {
    if sg_list.is_empty() {
        return Err(DriverError::InvalidDmaBuffer);
    }

    if sg_list.len() > max_entries {
        return Err(DriverError::InvalidDmaBuffer);
    }

    let mut total_size = 0usize;

    for (addr, len) in sg_list {
        validate_dma_buffer(PhysAddr::new(*addr), *len)?;

        total_size = total_size
            .checked_add(*len)
            .ok_or(DriverError::InvalidDmaBuffer)?;
    }

    if total_size > MAX_DMA_SIZE {
        return Err(DriverError::InvalidDmaBuffer);
    }

    Ok(total_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_dma_buffer_valid() {
        assert!(validate_dma_buffer(PhysAddr::new(0x5000_0000), 4096).is_ok());
    }

    #[test]
    fn test_validate_dma_buffer_kernel_region() {
        assert!(validate_dma_buffer(PhysAddr::new(0x1000), 4096).is_err());
    }

    #[test]
    fn test_validate_dma_buffer_zero_size() {
        assert!(validate_dma_buffer(PhysAddr::new(0x5000_0000), 0).is_err());
    }

    #[test]
    fn test_validate_dma_buffer_misaligned() {
        assert!(validate_dma_buffer(PhysAddr::new(0x5000_0001), 4096).is_err());
    }

    #[test]
    fn test_validate_dma_buffer_too_large() {
        assert!(validate_dma_buffer(PhysAddr::new(0x5000_0000), MAX_DMA_SIZE + 1).is_err());
    }

    #[test]
    fn test_validate_prp_list_valid() {
        let prp_list = [0x5000_0000u64, 0x5000_1000, 0x5000_2000];
        assert!(validate_prp_list(&prp_list, 4096 * 3).is_ok());
    }

    #[test]
    fn test_validate_prp_list_empty() {
        assert!(validate_prp_list(&[], 4096).is_err());
    }

    #[test]
    fn test_validate_prp_list_null_entry() {
        let prp_list = [0x5000_0000u64, 0, 0x5000_2000];
        assert!(validate_prp_list(&prp_list, 4096 * 3).is_err());
    }

    #[test]
    fn test_validate_prp_list_kernel_memory() {
        let prp_list = [0x1000u64];
        assert!(validate_prp_list(&prp_list, 4096).is_err());
    }
}
