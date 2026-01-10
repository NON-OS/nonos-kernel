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

use super::*;
use x86_64::PhysAddr;

#[test]
fn test_validate_mmio_region() {
    assert!(validate_mmio_region(0xE000_0000, 4096).is_ok());

    assert!(validate_mmio_region(0xFED0_0000, 4096).is_ok());

    assert!(validate_mmio_region(0xE000_0000, 0).is_err());

    assert!(validate_mmio_region(0xE000_0001, 4096).is_err());

    assert!(validate_mmio_region(0xFFFF_FFFF, 0x1000).is_err());

    assert!(validate_mmio_region(0x1000_0000, 4096).is_err());
}

#[test]
fn test_validate_dma_buffer() {
    assert!(validate_dma_buffer(PhysAddr::new(0x5000_0000), 4096).is_ok());

    assert!(validate_dma_buffer(PhysAddr::new(0x1000), 4096).is_err());

    assert!(validate_dma_buffer(PhysAddr::new(0x5000_0000), 0).is_err());

    assert!(validate_dma_buffer(PhysAddr::new(0x5000_0001), 4096).is_err());

    assert!(validate_dma_buffer(PhysAddr::new(0x5000_0000), MAX_DMA_SIZE + 1).is_err());
}

#[test]
fn test_validate_prp_list() {
    let prp_list = [0x5000_0000u64, 0x5000_1000, 0x5000_2000];
    assert!(validate_prp_list(&prp_list, 4096 * 3).is_ok());

    assert!(validate_prp_list(&[], 4096).is_err());

    let prp_list = [0x5000_0000u64, 0, 0x5000_2000];
    assert!(validate_prp_list(&prp_list, 4096 * 3).is_err());

    let prp_list = [0x1000u64];
    assert!(validate_prp_list(&prp_list, 4096).is_err());
}

#[test]
fn test_validate_pci_access() {
    assert!(validate_pci_access(0, 0, 0, 0).is_ok());
    assert!(validate_pci_access(255, 31, 7, 255).is_ok());

    assert!(validate_pci_access(0, 32, 0, 0).is_err());

    assert!(validate_pci_access(0, 0, 8, 0).is_err());
}

#[test]
fn test_config_write_protection() {
    assert!(!is_config_write_allowed(0x04));

    assert!(!is_config_write_allowed(0x3C));

    assert!(is_config_write_allowed(0x10));
    assert!(is_config_write_allowed(0x14));
}

#[test]
fn test_validate_lba_range() {
    assert!(validate_lba_range(0, 100, 1000).is_ok());

    assert!(validate_lba_range(900, 200, 1000).is_err());

    assert!(validate_lba_range(0, 0, 1000).is_err());

    assert!(validate_lba_range(u64::MAX - 10, 20, u64::MAX).is_err());
}

#[test]
fn test_partition_validation() {
    assert!(is_lba_in_partition(150, 100, 100));
    assert!(!is_lba_in_partition(250, 100, 100));

    assert!(validate_lba_in_partition(100, 50, 100, 100).is_ok());
    assert!(validate_lba_in_partition(99, 1, 100, 100).is_err());
}

#[test]
fn test_rate_limiter() {
    let limiter = RateLimiter::new(100);

    for _ in 0..100 {
        assert!(limiter.check_rate(DriverOpType::IoCommand).is_ok());
    }

    assert!(limiter.check_rate(DriverOpType::IoCommand).is_err());

    limiter.reset();
    assert!(limiter.check_rate(DriverOpType::IoCommand).is_ok());
}

#[test]
fn test_unlimited_rate_limiter() {
    let limiter = RateLimiter::new(0);

    for _ in 0..10000 {
        assert!(limiter.check_rate(DriverOpType::IoCommand).is_ok());
    }

    assert!(!limiter.is_exhausted());
    assert_eq!(limiter.remaining(), u64::MAX);
}

#[test]
fn test_rate_limiter_stats() {
    let limiter = RateLimiter::new(100);

    for _ in 0..50 {
        let _ = limiter.check_rate(DriverOpType::IoCommand);
    }

    let (count, max) = limiter.stats();
    assert_eq!(count, 50);
    assert_eq!(max, 100);
    assert_eq!(limiter.remaining(), 50);
}

#[test]
fn test_error_codes() {
    assert_eq!(DriverError::InvalidMmioRegion.code(), 0x1001);
    assert_eq!(DriverError::MmioAccessDenied.code(), 0x1002);
    assert_eq!(DriverError::InvalidDmaBuffer.code(), 0x2001);
    assert_eq!(DriverError::InvalidPrpList.code(), 0x2002);
    assert_eq!(DriverError::InvalidPciAccess.code(), 0x3001);
    assert_eq!(DriverError::ConfigWriteDenied.code(), 0x3002);
    assert_eq!(DriverError::LbaOutOfRange.code(), 0x4001);
}

#[test]
fn test_security_critical_errors() {
    assert!(DriverError::InvalidMmioRegion.is_security_critical());
    assert!(DriverError::MmioAccessDenied.is_security_critical());
    assert!(DriverError::InvalidDmaBuffer.is_security_critical());
    assert!(DriverError::InvalidPrpList.is_security_critical());
    assert!(DriverError::ConfigWriteDenied.is_security_critical());
    assert!(DriverError::IntegrityCheckFailed.is_security_critical());

    assert!(!DriverError::DeviceNotReady.is_security_critical());
    assert!(!DriverError::CommandTimeout.is_security_critical());
    assert!(!DriverError::RateLimitExceeded.is_security_critical());
}

#[test]
fn test_error_display() {
    assert_eq!(
        format!("{}", DriverError::InvalidMmioRegion),
        "Invalid MMIO region"
    );
    assert_eq!(
        format!("{}", DriverError::InvalidDmaBuffer),
        "Invalid DMA buffer"
    );
}

#[test]
fn test_driver_operation_flow() {
    let limiter = RateLimiter::new(1000);
    assert!(limiter.check_rate(DriverOpType::IoCommand).is_ok());

    assert!(validate_pci_access(0, 1, 0, 0).is_ok());

    assert!(validate_dma_buffer(PhysAddr::new(0x5000_0000), 4096).is_ok());

    assert!(validate_lba_range(0, 8, 1000000).is_ok());
}

#[test]
fn test_convenience_functions() {
    let io_limiter = io_rate_limiter();
    assert_eq!(io_limiter.stats().1, DEFAULT_IO_OPS_PER_SEC);

    let admin_limiter = admin_rate_limiter();
    assert_eq!(admin_limiter.stats().1, DEFAULT_ADMIN_OPS_PER_SEC);

    let dma_limiter = dma_rate_limiter();
    assert_eq!(dma_limiter.stats().1, DEFAULT_DMA_OPS_PER_SEC);
}
