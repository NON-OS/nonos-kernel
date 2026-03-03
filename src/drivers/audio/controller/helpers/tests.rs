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

use super::access::{spin_until, spin_while, RegisterAccess};
use super::super::super::constants::*;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

#[test]
fn test_spin_until_immediate() {
    let result = spin_until(|| true, 1000);
    assert!(result);
}

#[test]
fn test_spin_until_timeout() {
    let result = spin_until(|| false, 100);
    assert!(!result);
}

#[test]
fn test_spin_until_after_iterations() {
    let counter = RefCell::new(0);
    let result = spin_until(|| {
        let mut c = counter.borrow_mut();
        *c += 1;
        *c >= 5
    }, 1000);
    assert!(result);
    assert_eq!(*counter.borrow(), 5);
}

#[test]
fn test_spin_while_immediate() {
    let result = spin_while(|| false, 1000);
    assert!(result);
}

#[test]
fn test_spin_while_timeout() {
    let result = spin_while(|| true, 100);
    assert!(!result);
}

struct MockController {
    base: usize,
    regs: RefCell<Vec<u8>>,
}

impl MockController {
    fn new() -> Self {
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
    let new = ctrl.modify_reg32(0x40, 0x000000FF, 0xF0000000);
    assert_eq!(new, 0xFF00FF00);

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
    let addr1 = ctrl.stream_regs(1);
    assert_eq!(addr1, ctrl.base_addr() + STREAM_BASE);

    let addr2 = ctrl.stream_regs(2);
    assert_eq!(addr2, ctrl.base_addr() + STREAM_BASE + STREAM_STRIDE);
}
