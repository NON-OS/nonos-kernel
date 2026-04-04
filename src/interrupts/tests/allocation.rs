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

#[test]
fn test_vector_count() {
    assert_eq!(VECTOR_COUNT, 256);
}

#[test]
fn test_reserved_vectors_end() {
    assert_eq!(RESERVED_VECTORS_END, 32);
}

#[test]
fn test_timer_vector() {
    assert_eq!(TIMER_VECTOR, 32);
}

#[test]
fn test_keyboard_vector() {
    assert_eq!(KEYBOARD_VECTOR, 33);
}

#[test]
fn test_syscall_vector() {
    assert_eq!(SYSCALL_VECTOR, 0x80);
}

#[test]
fn test_reserved_vectors_below_32() {
    assert!(!is_vector_available(0));
    assert!(!is_vector_available(14));
    assert!(!is_vector_available(31));
}

#[test]
fn test_is_vector_available_checks_reserved() {
    for v in 0..RESERVED_VECTORS_END {
        assert!(!is_vector_available(v));
    }
}

#[test]
fn test_allocate_vector_returns_above_reserved() {
    if let Some(vector) = allocate_vector() {
        assert!(vector >= RESERVED_VECTORS_END);
        let _ = free_vector(vector);
    }
}

#[test]
fn test_allocate_and_free_vector() {
    if let Some(vector) = allocate_vector() {
        assert!(!is_vector_available(vector));
        assert!(free_vector(vector).is_ok());
        assert!(is_vector_available(vector));
    }
}

#[test]
fn test_free_reserved_vector_fails() {
    let result = free_vector(0);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "cannot free reserved vector");
}

#[test]
fn test_free_reserved_vector_31_fails() {
    let result = free_vector(31);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "cannot free reserved vector");
}

#[test]
fn test_free_unallocated_vector_fails() {
    if let Some(vector) = allocate_vector() {
        let _ = free_vector(vector);
        let result = free_vector(vector);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "vector not allocated");
    }
}

#[test]
fn test_register_handler_reserved_fails() {
    fn dummy_handler(_: x86_64::structures::idt::InterruptStackFrame) {}
    let result = register_interrupt_handler(0, dummy_handler);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "vector reserved for CPU exceptions");
}

#[test]
fn test_register_handler_reserved_31_fails() {
    fn dummy_handler(_: x86_64::structures::idt::InterruptStackFrame) {}
    let result = register_interrupt_handler(31, dummy_handler);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "vector reserved for CPU exceptions");
}

#[test]
fn test_unregister_handler_reserved_fails() {
    let result = unregister_handler(0);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "cannot unregister CPU exception handler");
}

#[test]
fn test_unregister_handler_reserved_31_fails() {
    let result = unregister_handler(31);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "cannot unregister CPU exception handler");
}

#[test]
fn test_get_handler_none_for_unregistered() {
    if let Some(vector) = allocate_vector() {
        assert!(get_handler(vector).is_none());
        let _ = free_vector(vector);
    }
}

#[test]
fn test_register_and_get_handler() {
    fn test_handler(_: x86_64::structures::idt::InterruptStackFrame) {}
    if let Some(vector) = allocate_vector() {
        assert!(register_interrupt_handler(vector, test_handler).is_ok());
        assert!(get_handler(vector).is_some());
        let _ = unregister_handler(vector);
        let _ = free_vector(vector);
    }
}

#[test]
fn test_register_handler_twice_fails() {
    fn handler1(_: x86_64::structures::idt::InterruptStackFrame) {}
    fn handler2(_: x86_64::structures::idt::InterruptStackFrame) {}
    if let Some(vector) = allocate_vector() {
        assert!(register_interrupt_handler(vector, handler1).is_ok());
        let result = register_interrupt_handler(vector, handler2);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "handler already registered");
        let _ = unregister_handler(vector);
        let _ = free_vector(vector);
    }
}

#[test]
fn test_unregister_and_register_handler() {
    fn handler1(_: x86_64::structures::idt::InterruptStackFrame) {}
    fn handler2(_: x86_64::structures::idt::InterruptStackFrame) {}
    if let Some(vector) = allocate_vector() {
        assert!(register_interrupt_handler(vector, handler1).is_ok());
        assert!(unregister_handler(vector).is_ok());
        assert!(register_interrupt_handler(vector, handler2).is_ok());
        let _ = unregister_handler(vector);
        let _ = free_vector(vector);
    }
}

#[test]
fn test_unregister_handler_none_fails() {
    if let Some(vector) = allocate_vector() {
        let result = unregister_handler(vector);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "no handler registered");
        let _ = free_vector(vector);
    }
}

#[test]
fn test_registry_exists() {
    let _guard = REGISTRY.read();
}

#[test]
fn test_multiple_allocations() {
    let mut allocated = alloc::vec::Vec::new();
    for _ in 0..10 {
        if let Some(vector) = allocate_vector() {
            assert!(!allocated.contains(&vector));
            allocated.push(vector);
        }
    }
    for vector in allocated {
        let _ = free_vector(vector);
    }
}
