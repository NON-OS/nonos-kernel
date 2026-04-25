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

use crate::interrupts::*;
use crate::test::framework::TestResult;

pub(crate) fn test_vector_count() -> TestResult {
    if VECTOR_COUNT != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reserved_vectors_end() -> TestResult {
    if RESERVED_VECTORS_END != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timer_vector() -> TestResult {
    if TIMER_VECTOR != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_vector() -> TestResult {
    if KEYBOARD_VECTOR != 33 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_vector() -> TestResult {
    if SYSCALL_VECTOR != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reserved_vectors_below_32() -> TestResult {
    if is_vector_available(0) {
        return TestResult::Fail;
    }
    if is_vector_available(14) {
        return TestResult::Fail;
    }
    if is_vector_available(31) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_vector_available_checks_reserved() -> TestResult {
    for v in 0..RESERVED_VECTORS_END {
        if is_vector_available(v) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_allocate_vector_returns_above_reserved() -> TestResult {
    if let Some(vector) = allocate_vector() {
        if vector < RESERVED_VECTORS_END {
            return TestResult::Fail;
        }
        let _ = free_vector(vector);
    }
    TestResult::Pass
}

pub(crate) fn test_allocate_and_free_vector() -> TestResult {
    if let Some(vector) = allocate_vector() {
        if is_vector_available(vector) {
            return TestResult::Fail;
        }
        if free_vector(vector).is_err() {
            return TestResult::Fail;
        }
        if !is_vector_available(vector) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_free_reserved_vector_fails() -> TestResult {
    let result = free_vector(0);
    if result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "cannot free reserved vector" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_free_reserved_vector_31_fails() -> TestResult {
    let result = free_vector(31);
    if result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "cannot free reserved vector" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_free_unallocated_vector_fails() -> TestResult {
    if let Some(vector) = allocate_vector() {
        let _ = free_vector(vector);
        let result = free_vector(vector);
        if result.is_ok() {
            return TestResult::Fail;
        }
        if result.unwrap_err() != "vector not allocated" {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_register_handler_reserved_fails() -> TestResult {
    fn dummy_handler(_: x86_64::structures::idt::InterruptStackFrame) {}
    let result = register_interrupt_handler(0, dummy_handler);
    if result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "vector reserved for CPU exceptions" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_handler_reserved_31_fails() -> TestResult {
    fn dummy_handler(_: x86_64::structures::idt::InterruptStackFrame) {}
    let result = register_interrupt_handler(31, dummy_handler);
    if result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "vector reserved for CPU exceptions" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unregister_handler_reserved_fails() -> TestResult {
    let result = unregister_handler(0);
    if result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "cannot unregister CPU exception handler" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unregister_handler_reserved_31_fails() -> TestResult {
    let result = unregister_handler(31);
    if result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "cannot unregister CPU exception handler" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_handler_none_for_unregistered() -> TestResult {
    if let Some(vector) = allocate_vector() {
        if get_handler(vector).is_some() {
            return TestResult::Fail;
        }
        let _ = free_vector(vector);
    }
    TestResult::Pass
}

pub(crate) fn test_register_and_get_handler() -> TestResult {
    fn test_handler(_: x86_64::structures::idt::InterruptStackFrame) {}
    if let Some(vector) = allocate_vector() {
        if register_interrupt_handler(vector, test_handler).is_err() {
            return TestResult::Fail;
        }
        if get_handler(vector).is_none() {
            return TestResult::Fail;
        }
        let _ = unregister_handler(vector);
        let _ = free_vector(vector);
    }
    TestResult::Pass
}

pub(crate) fn test_register_handler_twice_fails() -> TestResult {
    fn handler1(_: x86_64::structures::idt::InterruptStackFrame) {}
    fn handler2(_: x86_64::structures::idt::InterruptStackFrame) {}
    if let Some(vector) = allocate_vector() {
        if register_interrupt_handler(vector, handler1).is_err() {
            return TestResult::Fail;
        }
        let result = register_interrupt_handler(vector, handler2);
        if result.is_ok() {
            return TestResult::Fail;
        }
        if result.unwrap_err() != "handler already registered" {
            return TestResult::Fail;
        }
        let _ = unregister_handler(vector);
        let _ = free_vector(vector);
    }
    TestResult::Pass
}

pub(crate) fn test_unregister_and_register_handler() -> TestResult {
    fn handler1(_: x86_64::structures::idt::InterruptStackFrame) {}
    fn handler2(_: x86_64::structures::idt::InterruptStackFrame) {}
    if let Some(vector) = allocate_vector() {
        if register_interrupt_handler(vector, handler1).is_err() {
            return TestResult::Fail;
        }
        if unregister_handler(vector).is_err() {
            return TestResult::Fail;
        }
        if register_interrupt_handler(vector, handler2).is_err() {
            return TestResult::Fail;
        }
        let _ = unregister_handler(vector);
        let _ = free_vector(vector);
    }
    TestResult::Pass
}

pub(crate) fn test_unregister_handler_none_fails() -> TestResult {
    if let Some(vector) = allocate_vector() {
        let result = unregister_handler(vector);
        if result.is_ok() {
            return TestResult::Fail;
        }
        if result.unwrap_err() != "no handler registered" {
            return TestResult::Fail;
        }
        let _ = free_vector(vector);
    }
    TestResult::Pass
}

pub(crate) fn test_registry_exists() -> TestResult {
    let _guard = REGISTRY.read();
    TestResult::Pass
}

pub(crate) fn test_multiple_allocations() -> TestResult {
    let mut allocated = alloc::vec::Vec::new();
    for _ in 0..10 {
        if let Some(vector) = allocate_vector() {
            if allocated.contains(&vector) {
                return TestResult::Fail;
            }
            allocated.push(vector);
        }
    }
    for vector in allocated {
        let _ = free_vector(vector);
    }
    TestResult::Pass
}
