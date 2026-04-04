// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for arch/cpu.rs

use crate::arch::cpu::get_cpu_id;

#[test_case]
fn test_get_cpu_id_returns_valid() {
    let id = get_cpu_id();
    assert!(id < 256);
}

#[test_case]
fn test_get_cpu_id_consistent() {
    let id1 = get_cpu_id();
    let id2 = get_cpu_id();
    assert_eq!(id1, id2);
}

#[test_case]
fn test_cpu_id_is_zero_on_bsp() {
    let id = get_cpu_id();
    assert_eq!(id, 0);
}
