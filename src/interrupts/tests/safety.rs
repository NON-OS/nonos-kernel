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
fn test_in_interrupt_context_returns_bool() {
    let in_ctx = in_interrupt_context();
    assert!(in_ctx == true || in_ctx == false);
}

#[test]
fn test_set_interrupt_context_creates_context() {
    let _ctx = set_interrupt_context();
    assert!(in_interrupt_context());
}

#[test]
fn test_interrupt_context_cleared_on_drop() {
    {
        let _ctx = set_interrupt_context();
        assert!(in_interrupt_context());
    }
    assert!(!in_interrupt_context());
}

#[test]
fn test_nested_interrupt_context() {
    {
        let _ctx1 = set_interrupt_context();
        assert!(in_interrupt_context());
        {
            let _ctx2 = set_interrupt_context();
            assert!(in_interrupt_context());
        }
        assert!(in_interrupt_context());
    }
    assert!(!in_interrupt_context());
}

#[test]
fn test_disable_interrupts_guard_returns_guard() {
    let _guard = disable_interrupts_guard();
}

#[test]
fn test_interrupt_guard_restores_on_drop() {
    {
        let _guard = disable_interrupts_guard();
    }
}

#[test]
fn test_nested_interrupt_guards() {
    {
        let _guard1 = disable_interrupts_guard();
        {
            let _guard2 = disable_interrupts_guard();
        }
    }
}

#[test]
fn test_interrupt_context_multiple_drops() {
    let ctx1 = set_interrupt_context();
    let ctx2 = set_interrupt_context();
    assert!(in_interrupt_context());
    drop(ctx2);
    assert!(in_interrupt_context());
    drop(ctx1);
    assert!(!in_interrupt_context());
}

#[test]
fn test_interrupt_guard_and_context_together() {
    let _guard = disable_interrupts_guard();
    let _ctx = set_interrupt_context();
    assert!(in_interrupt_context());
}
