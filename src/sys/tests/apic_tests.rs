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

use crate::sys::apic::*;

#[test]
fn test_timer_vector_value() {
    assert_eq!(TIMER_VECTOR, 0x20);
}

#[test]
fn test_irq_timer_value() {
    assert_eq!(IRQ_TIMER, 0);
}

#[test]
fn test_irq_keyboard_value() {
    assert_eq!(IRQ_KEYBOARD, 1);
}

#[test]
fn test_irq_cascade_value() {
    assert_eq!(IRQ_CASCADE, 2);
}

#[test]
fn test_irq_com2_value() {
    assert_eq!(IRQ_COM2, 3);
}

#[test]
fn test_irq_com1_value() {
    assert_eq!(IRQ_COM1, 4);
}

#[test]
fn test_irq_lpt2_value() {
    assert_eq!(IRQ_LPT2, 5);
}

#[test]
fn test_irq_floppy_value() {
    assert_eq!(IRQ_FLOPPY, 6);
}

#[test]
fn test_irq_lpt1_value() {
    assert_eq!(IRQ_LPT1, 7);
}

#[test]
fn test_irq_rtc_value() {
    assert_eq!(IRQ_RTC, 8);
}

#[test]
fn test_irq_free1_value() {
    assert_eq!(IRQ_FREE1, 9);
}

#[test]
fn test_irq_free2_value() {
    assert_eq!(IRQ_FREE2, 10);
}

#[test]
fn test_irq_free3_value() {
    assert_eq!(IRQ_FREE3, 11);
}

#[test]
fn test_irq_mouse_value() {
    assert_eq!(IRQ_MOUSE, 12);
}

#[test]
fn test_irq_coprocessor_value() {
    assert_eq!(IRQ_COPROCESSOR, 13);
}

#[test]
fn test_irq_primary_ata_value() {
    assert_eq!(IRQ_PRIMARY_ATA, 14);
}

#[test]
fn test_irq_secondary_ata_value() {
    assert_eq!(IRQ_SECONDARY_ATA, 15);
}

#[test]
fn test_vector_timer_equals_timer_vector() {
    assert_eq!(VECTOR_TIMER, TIMER_VECTOR);
}

#[test]
fn test_vector_keyboard_value() {
    assert_eq!(VECTOR_KEYBOARD, 0x21);
}

#[test]
fn test_vector_mouse_value() {
    assert_eq!(VECTOR_MOUSE, 0x2C);
}

#[test]
fn test_vector_com1_value() {
    assert_eq!(VECTOR_COM1, 0x24);
}

#[test]
fn test_irq_to_vector_timer() {
    assert_eq!(irq_to_vector(IRQ_TIMER), 0x20);
}

#[test]
fn test_irq_to_vector_keyboard() {
    assert_eq!(irq_to_vector(IRQ_KEYBOARD), 0x21);
}

#[test]
fn test_irq_to_vector_mouse() {
    assert_eq!(irq_to_vector(IRQ_MOUSE), 0x2C);
}

#[test]
fn test_irq_to_vector_com1() {
    assert_eq!(irq_to_vector(IRQ_COM1), 0x24);
}

#[test]
fn test_irq_to_vector_com2() {
    assert_eq!(irq_to_vector(IRQ_COM2), 0x23);
}

#[test]
fn test_irq_to_vector_rtc() {
    assert_eq!(irq_to_vector(IRQ_RTC), 0x28);
}

#[test]
fn test_irq_to_vector_floppy() {
    assert_eq!(irq_to_vector(IRQ_FLOPPY), 0x26);
}

#[test]
fn test_irq_to_vector_primary_ata() {
    assert_eq!(irq_to_vector(IRQ_PRIMARY_ATA), 0x2E);
}

#[test]
fn test_irq_to_vector_secondary_ata() {
    assert_eq!(irq_to_vector(IRQ_SECONDARY_ATA), 0x2F);
}

#[test]
fn test_irq_to_vector_base_offset() {
    for irq in 0..16u8 {
        assert_eq!(irq_to_vector(irq), irq + 0x20);
    }
}

#[test]
fn test_vector_values_above_32() {
    assert!(VECTOR_TIMER >= 0x20);
    assert!(VECTOR_KEYBOARD >= 0x20);
    assert!(VECTOR_MOUSE >= 0x20);
    assert!(VECTOR_COM1 >= 0x20);
}

#[test]
fn test_irq_values_below_16() {
    assert!(IRQ_TIMER < 16);
    assert!(IRQ_KEYBOARD < 16);
    assert!(IRQ_CASCADE < 16);
    assert!(IRQ_COM2 < 16);
    assert!(IRQ_COM1 < 16);
    assert!(IRQ_LPT2 < 16);
    assert!(IRQ_FLOPPY < 16);
    assert!(IRQ_LPT1 < 16);
    assert!(IRQ_RTC < 16);
    assert!(IRQ_FREE1 < 16);
    assert!(IRQ_FREE2 < 16);
    assert!(IRQ_FREE3 < 16);
    assert!(IRQ_MOUSE < 16);
    assert!(IRQ_COPROCESSOR < 16);
    assert!(IRQ_PRIMARY_ATA < 16);
    assert!(IRQ_SECONDARY_ATA < 16);
}

#[test]
fn test_all_irqs_unique() {
    let irqs = [
        IRQ_TIMER, IRQ_KEYBOARD, IRQ_CASCADE, IRQ_COM2, IRQ_COM1, IRQ_LPT2,
        IRQ_FLOPPY, IRQ_LPT1, IRQ_RTC, IRQ_FREE1, IRQ_FREE2, IRQ_FREE3,
        IRQ_MOUSE, IRQ_COPROCESSOR, IRQ_PRIMARY_ATA, IRQ_SECONDARY_ATA,
    ];
    for i in 0..irqs.len() {
        for j in (i + 1)..irqs.len() {
            assert_ne!(irqs[i], irqs[j]);
        }
    }
}

#[test]
fn test_irq_to_vector_is_const() {
    const V: u8 = irq_to_vector(1);
    assert_eq!(V, 0x21);
}
