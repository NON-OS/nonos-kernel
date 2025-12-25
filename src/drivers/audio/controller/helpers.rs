// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! # Safety
//!
//! All MMIO operations in this module are inherently unsafe as they access
//! hardware registers. The safety is ensured by:
//!
//! 1. The base address is validated during controller initialization
//! 2. Register offsets are defined in `constants.rs` per the HDA specification
//! 3. The MMIO region remains mapped for the lifetime of the controller
//!
//! # Thread Safety
//!
//! Register access is not internally synchronized. Callers must ensure
//! proper synchronization (e.g., via Mutex) when accessing registers
//! from multiple threads.

use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::VirtAddr;

use crate::memory::mmio::{mmio_r8, mmio_r16, mmio_r32, mmio_w8, mmio_w16, mmio_w32};

use super::super::constants::*;

// =============================================================================
// Statistics for Debugging
// =============================================================================

/// Total spin loop iterations (for debugging/profiling).
static TOTAL_SPINS: AtomicU32 = AtomicU32::new(0);

/// Total spin timeouts (for debugging/profiling).
static SPIN_TIMEOUTS: AtomicU32 = AtomicU32::new(0);

/// Returns the total number of spin loop iterations performed.
#[inline]
pub fn total_spins() -> u32 {
    TOTAL_SPINS.load(Ordering::Relaxed)
}

/// Returns the number of spin timeout events.
#[inline]
pub fn spin_timeout_count() -> u32 {
    SPIN_TIMEOUTS.load(Ordering::Relaxed)
}

/// Resets spin statistics.
#[inline]
pub fn reset_spin_stats() {
    TOTAL_SPINS.store(0, Ordering::Relaxed);
    SPIN_TIMEOUTS.store(0, Ordering::Relaxed);
}

// =============================================================================
// Register Access Trait
// =============================================================================
/// # Safety: the methods in this trait perform direct MMIO operations. While the
/// methods themselves are safe, implementors must ensure:
/// 1. The base address points to a valid, mapped MMIO region
/// 2. The region remains mapped for the lifetime of register access
/// 3. Proper synchronization is used for concurrent access
pub trait RegisterAccess {
    fn base_addr(&self) -> usize;
    /// Reads a 32-bit register.
    #[inline]
    fn read_reg32(&self, offset: usize) -> u32 {
        debug_assert!(offset % 4 == 0, "32-bit register offset must be 4-byte aligned");
        // SAFETY: Caller ensures offset is valid HDA register.
        // base_addr points to mapped MMIO region.
        unsafe { mmio_r32(VirtAddr::new((self.base_addr() + offset) as u64)) }
    }

    /// Writes a 32-bit register.
    #[inline]
    fn write_reg32(&self, offset: usize, value: u32) {
        debug_assert!(offset % 4 == 0, "32-bit register offset must be 4-byte aligned");
        // SAFETY: Caller ensures offset is valid HDA register.
        unsafe { mmio_w32(VirtAddr::new((self.base_addr() + offset) as u64), value) }
    }

    /// Reads a 16-bit register.
    #[inline]
    fn read_reg16(&self, offset: usize) -> u16 {
        debug_assert!(offset % 2 == 0, "16-bit register offset must be 2-byte aligned");
        // SAFETY: Caller ensures offset is valid HDA register.
        unsafe { mmio_r16(VirtAddr::new((self.base_addr() + offset) as u64)) }
    }

    /// Writes a 16-bit register.
    #[inline]
    fn write_reg16(&self, offset: usize, value: u16) {
        debug_assert!(offset % 2 == 0, "16-bit register offset must be 2-byte aligned");
        // SAFETY: Caller ensures offset is valid HDA register.
        unsafe { mmio_w16(VirtAddr::new((self.base_addr() + offset) as u64), value) }
    }

    /// Reads an 8-bit register.
    #[inline]
    fn read_reg8(&self, offset: usize) -> u8 {
        // SAFETY: Caller ensures offset is valid HDA register.
        unsafe { mmio_r8(VirtAddr::new((self.base_addr() + offset) as u64)) }
    }

    /// Writes an 8-bit register.
    #[inline]
    fn write_reg8(&self, offset: usize, value: u8) {
        // SAFETY: Caller ensures offset is valid HDA register.
        unsafe { mmio_w8(VirtAddr::new((self.base_addr() + offset) as u64), value) }
    }

    /// Reads a register, masks it, and writes back with new bits.
    #[inline]
    fn modify_reg32(&self, offset: usize, clear_mask: u32, set_bits: u32) -> u32 {
        let current = self.read_reg32(offset);
        let new_value = (current & !clear_mask) | set_bits;
        self.write_reg32(offset, new_value);
        new_value
    }

    /// Sets specific bits in a 32-bit register.
    ///
    /// # Arguments
    ///
    /// * `offset` - Register offset
    /// * `bits` - Bits to set (OR with current value)
    #[inline]
    fn set_reg32_bits(&self, offset: usize, bits: u32) {
        let current = self.read_reg32(offset);
        self.write_reg32(offset, current | bits);
    }

    /// Clears specific bits in a 32-bit register.
    ///
    /// # Arguments
    ///
    /// * `offset` - Register offset
    /// * `bits` - Bits to clear (AND with ~bits)
    #[inline]
    fn clear_reg32_bits(&self, offset: usize, bits: u32) {
        let current = self.read_reg32(offset);
        self.write_reg32(offset, current & !bits);
    }

    /// Calculates the base address of a stream descriptor's register set.
    #[inline]
    fn stream_regs(&self, stream_index: u8) -> usize {
        debug_assert!(stream_index >= 1, "Stream index must be 1-based");
        debug_assert!((stream_index as usize) <= MAX_STREAMS, "Stream index out of range");
        self.base_addr() + STREAM_BASE + (stream_index as usize - 1) * STREAM_STRIDE
    }

    /// Reads a 32-bit stream descriptor register.
    ///
    /// # Arguments
    ///
    /// * `stream_index` - Stream index (1-based)
    /// * `offset` - Offset within stream descriptor (0x00-0x1C)
    #[inline]
    fn read_stream_reg32(&self, stream_index: u8, offset: usize) -> u32 {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        // SAFETY: Stream register offset is valid for initialized stream.
        unsafe { mmio_r32(VirtAddr::new(addr as u64)) }
    }

    /// Writes a 32-bit stream descriptor register.
    #[inline]
    fn write_stream_reg32(&self, stream_index: u8, offset: usize, value: u32) {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        // SAFETY: Stream register offset is valid for initialized stream.
        unsafe { mmio_w32(VirtAddr::new(addr as u64), value) }
    }

    /// Reads a 16-bit stream descriptor register.
    #[inline]
    fn read_stream_reg16(&self, stream_index: u8, offset: usize) -> u16 {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        // SAFETY: Stream register offset is valid for initialized stream.
        unsafe { mmio_r16(VirtAddr::new(addr as u64)) }
    }

    /// Writes a 16-bit stream descriptor register.
    #[inline]
    fn write_stream_reg16(&self, stream_index: u8, offset: usize, value: u16) {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        // SAFETY: Stream register offset is valid for initialized stream.
        unsafe { mmio_w16(VirtAddr::new(addr as u64), value) }
    }

    /// Reads an 8-bit stream descriptor register.
    #[inline]
    fn read_stream_reg8(&self, stream_index: u8, offset: usize) -> u8 {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        // SAFETY: Stream register offset is valid for initialized stream.
        unsafe { mmio_r8(VirtAddr::new(addr as u64)) }
    }

    /// Writes an 8-bit stream descriptor register.
    #[inline]
    fn write_stream_reg8(&self, stream_index: u8, offset: usize, value: u8) {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        // SAFETY: Stream register offset is valid for initialized stream.
        unsafe { mmio_w8(VirtAddr::new(addr as u64), value) }
    }

    /// Spins until a condition is met or timeout.
    #[inline]
    fn spin_until<F: Fn() -> bool>(&self, cond: F, max_spins: u32) -> bool {
        spin_until(cond, max_spins)
    }

    /// Spins while a condition is true or until timeout.
    #[inline]
    fn spin_while<F: Fn() -> bool>(&self, cond: F, max_spins: u32) -> bool {
        spin_while(cond, max_spins)
    }
}

// =============================================================================
// Spin Loop Utilities
// =============================================================================
/// Spins until a condition is met or timeout.

#[inline]
pub fn spin_until<F: Fn() -> bool>(cond: F, mut max_spins: u32) -> bool {
    let start_spins = max_spins;

    while max_spins > 0 {
        if cond() {
            // Update statistics
            let iterations = start_spins - max_spins + 1;
            TOTAL_SPINS.fetch_add(iterations, Ordering::Relaxed);
            return true;
        }
        // Hint to the CPU that we're in a spin loop
        // This can improve performance on hyperthreaded cores
        core::hint::spin_loop();
        max_spins -= 1;
    }

    // Update statistics - timeout occurred
    TOTAL_SPINS.fetch_add(start_spins, Ordering::Relaxed);
    SPIN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    false
}

/// Spins while a condition is true or until timeout.
#[inline]
pub fn spin_while<F: Fn() -> bool>(cond: F, mut max_spins: u32) -> bool {
    let start_spins = max_spins;

    while max_spins > 0 {
        if !cond() {
            let iterations = start_spins - max_spins + 1;
            TOTAL_SPINS.fetch_add(iterations, Ordering::Relaxed);
            return true;
        }
        core::hint::spin_loop();
        max_spins -= 1;
    }

    TOTAL_SPINS.fetch_add(start_spins, Ordering::Relaxed);
    SPIN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    false
}

/// Spins for a fixed number of iterations.
/// # Note
/// This should only be used for short delays required by hardware.

#[inline]
pub fn spin_delay(mut count: u32) {
    while count > 0 {
        core::hint::spin_loop();
        count -= 1;
    }
}

// =============================================================================
// Register Debugging Helpers
// =============================================================================
/// Dumps the main controller registers for debugging.
pub fn dump_controller_regs<T: RegisterAccess>(ctrl: &T) -> alloc::string::String {
    use alloc::format;

    format!(
        "HDA Registers:\n\
         GCAP:     0x{:04X}\n\
         VMIN/MAJ: {}.{}\n\
         GCTL:     0x{:08X}\n\
         WAKEEN:   0x{:04X}\n\
         STATESTS: 0x{:04X}\n\
         INTCTL:   0x{:08X}\n\
         INTSTS:   0x{:08X}\n\
         CORBWP:   0x{:04X}\n\
         CORBRP:   0x{:04X}\n\
         RIRBWP:   0x{:04X}",
        ctrl.read_reg16(GCAP),
        ctrl.read_reg8(VMAJ),
        ctrl.read_reg8(VMIN),
        ctrl.read_reg32(GCTL),
        ctrl.read_reg16(WAKEEN),
        ctrl.read_reg16(STATESTS),
        ctrl.read_reg32(INTCTL),
        ctrl.read_reg32(INTSTS),
        ctrl.read_reg16(CORBWP),
        ctrl.read_reg16(CORBRP),
        ctrl.read_reg16(RIRBWP),
    )
}

/// Dumps a stream descriptor's registers for debugging.
pub fn dump_stream_regs<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> alloc::string::String {
    use alloc::format;

    format!(
        "Stream {} Registers:\n\
         CTL:   0x{:08X}\n\
         STS:   0x{:02X}\n\
         LPIB:  0x{:08X}\n\
         CBL:   0x{:08X}\n\
         LVI:   0x{:04X}\n\
         FIFOS: 0x{:04X}\n\
         FMT:   0x{:04X}\n\
         BDPL:  0x{:08X}\n\
         BDPU:  0x{:08X}",
        stream_index,
        ctrl.read_stream_reg32(stream_index, SD_CTL),
        ctrl.read_stream_reg8(stream_index, SD_STS),
        ctrl.read_stream_reg32(stream_index, SD_LPIB),
        ctrl.read_stream_reg32(stream_index, SD_CBL),
        ctrl.read_stream_reg16(stream_index, SD_LVI),
        ctrl.read_stream_reg16(stream_index, SD_FIFOS),
        ctrl.read_stream_reg16(stream_index, SD_FMT),
        ctrl.read_stream_reg32(stream_index, SD_BDPL),
        ctrl.read_stream_reg32(stream_index, SD_BDPU),
    )
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    // =========================================================================
    // Spin Function Tests
    // =========================================================================

    #[test]
    fn test_spin_until_immediate() {
        reset_spin_stats();
        let result = spin_until(|| true, 1000);
        assert!(result);
        assert!(total_spins() >= 1);
        assert_eq!(spin_timeout_count(), 0);
    }

    #[test]
    fn test_spin_until_timeout() {
        reset_spin_stats();
        let result = spin_until(|| false, 100);
        assert!(!result);
        assert_eq!(total_spins(), 100);
        assert_eq!(spin_timeout_count(), 1);
    }

    #[test]
    fn test_spin_until_after_iterations() {
        reset_spin_stats();
        let counter = RefCell::new(0);
        let result = spin_until(|| {
            let mut c = counter.borrow_mut();
            *c += 1;
            *c >= 5
        }, 1000);
        assert!(result);
        assert_eq!(*counter.borrow(), 5);
        assert!(total_spins() >= 5);
        assert_eq!(spin_timeout_count(), 0);
    }

    #[test]
    fn test_spin_while_immediate() {
        reset_spin_stats();
        let result = spin_while(|| false, 1000);
        assert!(result);
        assert!(total_spins() >= 1);
        assert_eq!(spin_timeout_count(), 0);
    }

    #[test]
    fn test_spin_while_timeout() {
        reset_spin_stats();
        let result = spin_while(|| true, 100);
        assert!(!result);
        assert_eq!(total_spins(), 100);
        assert_eq!(spin_timeout_count(), 1);
    }

    #[test]
    fn test_spin_while_after_iterations() {
        reset_spin_stats();
        let counter = RefCell::new(0);
        let result = spin_while(|| {
            let mut c = counter.borrow_mut();
            *c += 1;
            *c < 5
        }, 1000);
        assert!(result);
        assert_eq!(*counter.borrow(), 5);
        assert!(total_spins() >= 5);
        assert_eq!(spin_timeout_count(), 0);
    }

    #[test]
    fn test_spin_delay() {
        // Just verify it runs without panicking
        spin_delay(0);
        spin_delay(1);
        spin_delay(10);
        spin_delay(100);
    }

    // =========================================================================
    // Statistics Tests
    // =========================================================================

    #[test]
    fn test_reset_spin_stats() {
        // Accumulate some stats
        spin_until(|| false, 50);
        spin_while(|| true, 50);
        assert!(total_spins() > 0);
        assert!(spin_timeout_count() > 0);

        // Reset and verify
        reset_spin_stats();
        assert_eq!(total_spins(), 0);
        assert_eq!(spin_timeout_count(), 0);
    }

    #[test]
    fn test_spin_stats_accumulate() {
        reset_spin_stats();

        // First timeout
        spin_until(|| false, 10);
        assert_eq!(total_spins(), 10);
        assert_eq!(spin_timeout_count(), 1);

        // Second timeout
        spin_until(|| false, 20);
        assert_eq!(total_spins(), 30);
        assert_eq!(spin_timeout_count(), 2);

        // Successful spin
        spin_until(|| true, 100);
        assert!(total_spins() >= 31);
        assert_eq!(spin_timeout_count(), 2);
    }

    // =========================================================================
    // Mock Controller for RegisterAccess Tests
    // =========================================================================

    /// Mock controller with simulated register space for testing.
    struct MockController {
        base: usize,
        regs: RefCell<Vec<u8>>,
    }

    impl MockController {
        fn new() -> Self {
            // Create a 4KB simulated register space
            Self {
                base: 0x1000,
                regs: RefCell::new(vec![0u8; 4096]),
            }
        }

        fn set_reg8(&self, offset: usize, value: u8) {
            self.regs.borrow_mut()[offset] = value;
        }

        fn set_reg16(&self, offset: usize, value: u16) {
            let bytes = value.to_le_bytes();
            let mut regs = self.regs.borrow_mut();
            regs[offset] = bytes[0];
            regs[offset + 1] = bytes[1];
        }

        fn set_reg32(&self, offset: usize, value: u32) {
            let bytes = value.to_le_bytes();
            let mut regs = self.regs.borrow_mut();
            regs[offset] = bytes[0];
            regs[offset + 1] = bytes[1];
            regs[offset + 2] = bytes[2];
            regs[offset + 3] = bytes[3];
        }

        fn get_reg8(&self, offset: usize) -> u8 {
            self.regs.borrow()[offset]
        }

        fn get_reg16(&self, offset: usize) -> u16 {
            let regs = self.regs.borrow();
            u16::from_le_bytes([regs[offset], regs[offset + 1]])
        }

        fn get_reg32(&self, offset: usize) -> u32 {
            let regs = self.regs.borrow();
            u32::from_le_bytes([
                regs[offset],
                regs[offset + 1],
                regs[offset + 2],
                regs[offset + 3],
            ])
        }
    }

    impl RegisterAccess for MockController {
        fn base_addr(&self) -> usize {
            self.base
        }

        // Override MMIO methods to use our mock register space
        fn read_reg8(&self, offset: usize) -> u8 {
            self.get_reg8(offset)
        }

        fn write_reg8(&self, offset: usize, value: u8) {
            self.set_reg8(offset, value);
        }

        fn read_reg16(&self, offset: usize) -> u16 {
            self.get_reg16(offset)
        }

        fn write_reg16(&self, offset: usize, value: u16) {
            self.set_reg16(offset, value);
        }

        fn read_reg32(&self, offset: usize) -> u32 {
            self.get_reg32(offset)
        }

        fn write_reg32(&self, offset: usize, value: u32) {
            self.set_reg32(offset, value);
        }
    }

    // =========================================================================
    // RegisterAccess Trait Tests
    // =========================================================================

    #[test]
    fn test_register_access_base_addr() {
        let ctrl = MockController::new();
        assert_eq!(ctrl.base_addr(), 0x1000);
    }

    #[test]
    fn test_register_access_read_write_8() {
        let ctrl = MockController::new();
        ctrl.write_reg8(0x10, 0xAB);
        assert_eq!(ctrl.read_reg8(0x10), 0xAB);
    }

    #[test]
    fn test_register_access_read_write_16() {
        let ctrl = MockController::new();
        ctrl.write_reg16(0x20, 0xABCD);
        assert_eq!(ctrl.read_reg16(0x20), 0xABCD);
    }

    #[test]
    fn test_register_access_read_write_32() {
        let ctrl = MockController::new();
        ctrl.write_reg32(0x30, 0xDEADBEEF);
        assert_eq!(ctrl.read_reg32(0x30), 0xDEADBEEF);
    }

    #[test]
    fn test_modify_reg32() {
        let ctrl = MockController::new();
        ctrl.write_reg32(0x40, 0xFF00FF00);

        // Clear low byte, set high nibble
        let new = ctrl.modify_reg32(0x40, 0x000000FF, 0xF0000000);
        assert_eq!(new, 0xFF00FF00);  // Nothing in low byte to clear

        ctrl.write_reg32(0x40, 0x000000FF);
        let new = ctrl.modify_reg32(0x40, 0x000000FF, 0xABCD0000);
        assert_eq!(new, 0xABCD0000);
    }

    #[test]
    fn test_set_reg32_bits() {
        let ctrl = MockController::new();
        ctrl.write_reg32(0x50, 0x00FF0000);
        ctrl.set_reg32_bits(0x50, 0x0000FF00);
        assert_eq!(ctrl.read_reg32(0x50), 0x00FFFF00);
    }

    #[test]
    fn test_clear_reg32_bits() {
        let ctrl = MockController::new();
        ctrl.write_reg32(0x60, 0xFFFFFFFF);
        ctrl.clear_reg32_bits(0x60, 0x00FF00FF);
        assert_eq!(ctrl.read_reg32(0x60), 0xFF00FF00);
    }

    #[test]
    fn test_stream_regs_calculation() {
        let ctrl = MockController::new();
        // Stream 1 should be at base + STREAM_BASE + 0 * STREAM_STRIDE
        let addr1 = ctrl.stream_regs(1);
        assert_eq!(addr1, ctrl.base_addr() + STREAM_BASE);

        // Stream 2 should be at base + STREAM_BASE + 1 * STREAM_STRIDE
        let addr2 = ctrl.stream_regs(2);
        assert_eq!(addr2, ctrl.base_addr() + STREAM_BASE + STREAM_STRIDE);
    }

    #[test]
    fn test_stream_reg_read_write_8() {
        let ctrl = MockController::new();
        // Calculate where stream 1's registers start (relative to base)
        let stream_offset = STREAM_BASE;

        // Write via stream accessor, read via mock
        ctrl.write_stream_reg8(1, 0x03, 0x55);
        assert_eq!(ctrl.get_reg8(stream_offset + 0x03), 0x55);

        // Write via mock, read via stream accessor
        ctrl.set_reg8(stream_offset + 0x04, 0xAA);
        assert_eq!(ctrl.read_stream_reg8(1, 0x04), 0xAA);
    }

    #[test]
    fn test_stream_reg_read_write_16() {
        let ctrl = MockController::new();
        let stream_offset = STREAM_BASE;

        ctrl.write_stream_reg16(1, 0x02, 0x1234);
        assert_eq!(ctrl.get_reg16(stream_offset + 0x02), 0x1234);

        ctrl.set_reg16(stream_offset + 0x06, 0xABCD);
        assert_eq!(ctrl.read_stream_reg16(1, 0x06), 0xABCD);
    }

    #[test]
    fn test_stream_reg_read_write_32() {
        let ctrl = MockController::new();
        let stream_offset = STREAM_BASE;

        ctrl.write_stream_reg32(1, 0x00, 0xDEADBEEF);
        assert_eq!(ctrl.get_reg32(stream_offset + 0x00), 0xDEADBEEF);

        ctrl.set_reg32(stream_offset + 0x04, 0xCAFEBABE);
        assert_eq!(ctrl.read_stream_reg32(1, 0x04), 0xCAFEBABE);
    }

    #[test]
    fn test_spin_until_trait_method() {
        reset_spin_stats();
        let ctrl = MockController::new();

        let result = ctrl.spin_until(|| true, 100);
        assert!(result);
        assert!(total_spins() >= 1);
    }

    #[test]
    fn test_spin_while_trait_method() {
        reset_spin_stats();
        let ctrl = MockController::new();

        let result = ctrl.spin_while(|| false, 100);
        assert!(result);
        assert!(total_spins() >= 1);
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_spin_until_zero_max() {
        reset_spin_stats();
        let result = spin_until(|| true, 0);
        assert!(!result);  // Should timeout immediately
        assert_eq!(spin_timeout_count(), 1);
    }

    #[test]
    fn test_spin_while_zero_max() {
        reset_spin_stats();
        let result = spin_while(|| false, 0);
        assert!(!result);  // Should timeout immediately
        assert_eq!(spin_timeout_count(), 1);
    }

    #[test]
    fn test_register_endianness() {
        let ctrl = MockController::new();

        // Write bytes in expected order
        ctrl.write_reg8(0x00, 0x01);
        ctrl.write_reg8(0x01, 0x02);
        ctrl.write_reg8(0x02, 0x03);
        ctrl.write_reg8(0x03, 0x04);

        // 16-bit read should be little-endian
        assert_eq!(ctrl.read_reg16(0x00), 0x0201);
        assert_eq!(ctrl.read_reg16(0x02), 0x0403);

        // 32-bit read should be little-endian
        assert_eq!(ctrl.read_reg32(0x00), 0x04030201);
    }

    #[test]
    fn test_modify_preserves_other_bits() {
        let ctrl = MockController::new();
        ctrl.write_reg32(0x70, 0x12345678);

        // Only modify the middle byte
        ctrl.modify_reg32(0x70, 0x0000FF00, 0x0000AA00);
        assert_eq!(ctrl.read_reg32(0x70), 0x1234AA78);
    }
}
