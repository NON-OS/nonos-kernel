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

use core::mem::size_of;
use super::*;

#[test]
fn test_error_messages() {
    assert_eq!(IdtError::None.as_str(), "no error");
    assert_eq!(IdtError::NotInitialized.as_str(), "IDT not initialized");
    assert_eq!(
        IdtError::InvalidVector.as_str(),
        "invalid interrupt vector number"
    );
}

#[test]
fn test_idt_entry_size() {
    assert_eq!(size_of::<IdtEntry>(), 16);
}

#[test]
fn test_idt_entry_empty() {
    let entry = IdtEntry::empty();
    assert!(!entry.is_present());
    assert_eq!(entry.handler(), 0);
}

#[test]
fn test_idt_entry_interrupt_gate() {
    let entry = IdtEntry::interrupt_gate(0x12345678_9ABCDEF0u64, KERNEL_CS, 3, DPL_KERNEL);
    assert!(entry.is_present());
    assert_eq!(entry.handler(), 0x12345678_9ABCDEF0);
    assert_eq!(entry.ist(), 3);
    assert_eq!(entry.dpl(), 0);
    assert!(!entry.is_trap());
}

#[test]
fn test_idt_entry_trap_gate() {
    let entry = IdtEntry::trap_gate(0xDEADBEEFu64, KERNEL_CS, 0, DPL_USER);
    assert!(entry.is_present());
    assert_eq!(entry.dpl(), 3);
    assert!(entry.is_trap());
}

#[test]
fn test_page_fault_error() {
    let error = PageFaultError(0b10101);
    assert!(error.protection_violation());
    assert!(!error.write());
    assert!(error.user());
    assert!(!error.reserved_write());
    assert!(error.instruction_fetch());
}

#[test]
fn test_vector_constants() {
    assert_eq!(VEC_DIVIDE_ERROR, 0);
    assert_eq!(VEC_PAGE_FAULT, 14);
    assert_eq!(VEC_DOUBLE_FAULT, 8);
    assert_eq!(IRQ_BASE, 32);
}

#[test]
fn test_ist_constants() {
    assert_eq!(IST_DOUBLE_FAULT, 1);
    assert_eq!(IST_NMI, 2);
    assert_eq!(IST_MACHINE_CHECK, 3);
}
