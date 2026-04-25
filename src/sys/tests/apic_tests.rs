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
use crate::test::framework::TestResult;

pub(crate) fn test_timer_vector_value() -> TestResult {
    if TIMER_VECTOR != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_timer_value() -> TestResult {
    if IRQ_TIMER != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_keyboard_value() -> TestResult {
    if IRQ_KEYBOARD != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_cascade_value() -> TestResult {
    if IRQ_CASCADE != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_com2_value() -> TestResult {
    if IRQ_COM2 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_com1_value() -> TestResult {
    if IRQ_COM1 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_lpt2_value() -> TestResult {
    if IRQ_LPT2 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_floppy_value() -> TestResult {
    if IRQ_FLOPPY != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_lpt1_value() -> TestResult {
    if IRQ_LPT1 != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_rtc_value() -> TestResult {
    if IRQ_RTC != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_free1_value() -> TestResult {
    if IRQ_FREE1 != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_free2_value() -> TestResult {
    if IRQ_FREE2 != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_free3_value() -> TestResult {
    if IRQ_FREE3 != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_mouse_value() -> TestResult {
    if IRQ_MOUSE != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_coprocessor_value() -> TestResult {
    if IRQ_COPROCESSOR != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_primary_ata_value() -> TestResult {
    if IRQ_PRIMARY_ATA != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_secondary_ata_value() -> TestResult {
    if IRQ_SECONDARY_ATA != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_timer_equals_timer_vector() -> TestResult {
    if VECTOR_TIMER != TIMER_VECTOR {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_keyboard_value() -> TestResult {
    if VECTOR_KEYBOARD != 0x21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_mouse_value() -> TestResult {
    if VECTOR_MOUSE != 0x2C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_com1_value() -> TestResult {
    if VECTOR_COM1 != 0x24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_timer() -> TestResult {
    if irq_to_vector(IRQ_TIMER) != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_keyboard() -> TestResult {
    if irq_to_vector(IRQ_KEYBOARD) != 0x21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_mouse() -> TestResult {
    if irq_to_vector(IRQ_MOUSE) != 0x2C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_com1() -> TestResult {
    if irq_to_vector(IRQ_COM1) != 0x24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_com2() -> TestResult {
    if irq_to_vector(IRQ_COM2) != 0x23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_rtc() -> TestResult {
    if irq_to_vector(IRQ_RTC) != 0x28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_floppy() -> TestResult {
    if irq_to_vector(IRQ_FLOPPY) != 0x26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_primary_ata() -> TestResult {
    if irq_to_vector(IRQ_PRIMARY_ATA) != 0x2E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_secondary_ata() -> TestResult {
    if irq_to_vector(IRQ_SECONDARY_ATA) != 0x2F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_base_offset() -> TestResult {
    for irq in 0..16u8 {
        if irq_to_vector(irq) != irq + 0x20 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vector_values_above_32() -> TestResult {
    if !(VECTOR_TIMER >= 0x20) {
        return TestResult::Fail;
    }
    if !(VECTOR_KEYBOARD >= 0x20) {
        return TestResult::Fail;
    }
    if !(VECTOR_MOUSE >= 0x20) {
        return TestResult::Fail;
    }
    if !(VECTOR_COM1 >= 0x20) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_values_below_16() -> TestResult {
    if !(IRQ_TIMER < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_KEYBOARD < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_CASCADE < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_COM2 < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_COM1 < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_LPT2 < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_FLOPPY < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_LPT1 < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_RTC < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_FREE1 < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_FREE2 < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_FREE3 < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_MOUSE < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_COPROCESSOR < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_PRIMARY_ATA < 16) {
        return TestResult::Fail;
    }
    if !(IRQ_SECONDARY_ATA < 16) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_irqs_unique() -> TestResult {
    let irqs = [
        IRQ_TIMER,
        IRQ_KEYBOARD,
        IRQ_CASCADE,
        IRQ_COM2,
        IRQ_COM1,
        IRQ_LPT2,
        IRQ_FLOPPY,
        IRQ_LPT1,
        IRQ_RTC,
        IRQ_FREE1,
        IRQ_FREE2,
        IRQ_FREE3,
        IRQ_MOUSE,
        IRQ_COPROCESSOR,
        IRQ_PRIMARY_ATA,
        IRQ_SECONDARY_ATA,
    ];
    for i in 0..irqs.len() {
        for j in (i + 1)..irqs.len() {
            if irqs[i] == irqs[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector_is_const() -> TestResult {
    const V: u8 = irq_to_vector(1);
    if V != 0x21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
