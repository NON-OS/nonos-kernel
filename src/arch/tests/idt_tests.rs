// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for arch/x86_64/idt

use crate::arch::x86_64::idt::{
    IDT_ENTRIES, KERNEL_CS, GATE_INTERRUPT, GATE_TRAP, DPL_KERNEL, DPL_USER, PRESENT,
    VEC_DIVIDE_ERROR, VEC_DEBUG, VEC_NMI, VEC_BREAKPOINT, VEC_OVERFLOW, VEC_BOUND_RANGE,
    VEC_INVALID_OPCODE, VEC_DEVICE_NOT_AVAILABLE, VEC_DOUBLE_FAULT, VEC_COPROCESSOR_SEGMENT,
    VEC_INVALID_TSS, VEC_SEGMENT_NOT_PRESENT, VEC_STACK_SEGMENT, VEC_GENERAL_PROTECTION,
    VEC_PAGE_FAULT, VEC_X87_FP, VEC_ALIGNMENT_CHECK, VEC_MACHINE_CHECK, VEC_SIMD_FP,
    VEC_VIRTUALIZATION, VEC_CONTROL_PROTECTION, IRQ_BASE,
    IST_DOUBLE_FAULT, IST_NMI, IST_MACHINE_CHECK, IST_DEBUG, IST_PAGE_FAULT, IST_GP,
};

#[test_case]
fn test_idt_entries_count() {
    assert_eq!(IDT_ENTRIES, 256);
}

#[test_case]
fn test_kernel_cs() {
    assert_eq!(KERNEL_CS, 0x08);
}

#[test_case]
fn test_gate_types() {
    assert_eq!(GATE_INTERRUPT, 0x0E);
    assert_eq!(GATE_TRAP, 0x0F);
}

#[test_case]
fn test_privilege_levels() {
    assert_eq!(DPL_KERNEL, 0);
    assert_eq!(DPL_USER, 3);
}

#[test_case]
fn test_present_flag() {
    assert_eq!(PRESENT, 0x80);
}

#[test_case]
fn test_exception_vectors_order() {
    assert_eq!(VEC_DIVIDE_ERROR, 0);
    assert_eq!(VEC_DEBUG, 1);
    assert_eq!(VEC_NMI, 2);
    assert_eq!(VEC_BREAKPOINT, 3);
    assert_eq!(VEC_OVERFLOW, 4);
    assert_eq!(VEC_BOUND_RANGE, 5);
    assert_eq!(VEC_INVALID_OPCODE, 6);
    assert_eq!(VEC_DEVICE_NOT_AVAILABLE, 7);
    assert_eq!(VEC_DOUBLE_FAULT, 8);
}

#[test_case]
fn test_exception_vectors_high() {
    assert_eq!(VEC_COPROCESSOR_SEGMENT, 9);
    assert_eq!(VEC_INVALID_TSS, 10);
    assert_eq!(VEC_SEGMENT_NOT_PRESENT, 11);
    assert_eq!(VEC_STACK_SEGMENT, 12);
    assert_eq!(VEC_GENERAL_PROTECTION, 13);
    assert_eq!(VEC_PAGE_FAULT, 14);
    assert_eq!(VEC_X87_FP, 16);
    assert_eq!(VEC_ALIGNMENT_CHECK, 17);
    assert_eq!(VEC_MACHINE_CHECK, 18);
    assert_eq!(VEC_SIMD_FP, 19);
    assert_eq!(VEC_VIRTUALIZATION, 20);
    assert_eq!(VEC_CONTROL_PROTECTION, 21);
}

#[test_case]
fn test_irq_base() {
    assert_eq!(IRQ_BASE, 32);
}

#[test_case]
fn test_irq_base_after_exceptions() {
    assert!(IRQ_BASE as usize > VEC_CONTROL_PROTECTION as usize);
}

#[test_case]
fn test_ist_indices() {
    assert_eq!(IST_DOUBLE_FAULT, 1);
    assert_eq!(IST_NMI, 2);
    assert_eq!(IST_MACHINE_CHECK, 3);
    assert_eq!(IST_DEBUG, 4);
    assert_eq!(IST_PAGE_FAULT, 5);
    assert_eq!(IST_GP, 6);
}

#[test_case]
fn test_ist_indices_valid_range() {
    assert!(IST_DOUBLE_FAULT <= 7);
    assert!(IST_NMI <= 7);
    assert!(IST_MACHINE_CHECK <= 7);
    assert!(IST_DEBUG <= 7);
    assert!(IST_PAGE_FAULT <= 7);
    assert!(IST_GP <= 7);
}

#[test_case]
fn test_ist_indices_nonzero() {
    assert!(IST_DOUBLE_FAULT > 0);
    assert!(IST_NMI > 0);
    assert!(IST_MACHINE_CHECK > 0);
    assert!(IST_DEBUG > 0);
    assert!(IST_PAGE_FAULT > 0);
    assert!(IST_GP > 0);
}

#[test_case]
fn test_exceptions_below_irq_base() {
    assert!(VEC_DIVIDE_ERROR < IRQ_BASE);
    assert!(VEC_DOUBLE_FAULT < IRQ_BASE);
    assert!(VEC_PAGE_FAULT < IRQ_BASE);
    assert!(VEC_GENERAL_PROTECTION < IRQ_BASE);
}

#[test_case]
fn test_all_exceptions_unique() {
    let exceptions = [
        VEC_DIVIDE_ERROR, VEC_DEBUG, VEC_NMI, VEC_BREAKPOINT, VEC_OVERFLOW,
        VEC_BOUND_RANGE, VEC_INVALID_OPCODE, VEC_DEVICE_NOT_AVAILABLE,
        VEC_DOUBLE_FAULT, VEC_COPROCESSOR_SEGMENT, VEC_INVALID_TSS,
        VEC_SEGMENT_NOT_PRESENT, VEC_STACK_SEGMENT, VEC_GENERAL_PROTECTION,
        VEC_PAGE_FAULT, VEC_X87_FP, VEC_ALIGNMENT_CHECK, VEC_MACHINE_CHECK,
        VEC_SIMD_FP, VEC_VIRTUALIZATION, VEC_CONTROL_PROTECTION,
    ];

    for i in 0..exceptions.len() {
        for j in (i + 1)..exceptions.len() {
            assert_ne!(exceptions[i], exceptions[j]);
        }
    }
}

#[test_case]
fn test_idt_size_fits_256_entries() {
    assert!(IDT_ENTRIES <= 256);
}
