// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::arch::x86_64::idt::{
    DPL_KERNEL, DPL_USER, GATE_INTERRUPT, GATE_TRAP, IDT_ENTRIES, IRQ_BASE, IST_DEBUG,
    IST_DOUBLE_FAULT, IST_GP, IST_MACHINE_CHECK, IST_NMI, IST_PAGE_FAULT, KERNEL_CS, PRESENT,
    VEC_ALIGNMENT_CHECK, VEC_BOUND_RANGE, VEC_BREAKPOINT, VEC_CONTROL_PROTECTION,
    VEC_COPROCESSOR_SEGMENT, VEC_DEBUG, VEC_DEVICE_NOT_AVAILABLE, VEC_DIVIDE_ERROR,
    VEC_DOUBLE_FAULT, VEC_GENERAL_PROTECTION, VEC_INVALID_OPCODE, VEC_INVALID_TSS,
    VEC_MACHINE_CHECK, VEC_NMI, VEC_OVERFLOW, VEC_PAGE_FAULT, VEC_SEGMENT_NOT_PRESENT, VEC_SIMD_FP,
    VEC_STACK_SEGMENT, VEC_VIRTUALIZATION, VEC_X87_FP,
};
use crate::test::framework::TestResult;

pub(crate) fn test_idt_entries_count() -> TestResult {
    if IDT_ENTRIES != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_cs() -> TestResult {
    if KERNEL_CS != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gate_types() -> TestResult {
    if GATE_INTERRUPT != 0x0E {
        return TestResult::Fail;
    }
    if GATE_TRAP != 0x0F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_privilege_levels() -> TestResult {
    if DPL_KERNEL != 0 {
        return TestResult::Fail;
    }
    if DPL_USER != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_present_flag() -> TestResult {
    if PRESENT != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_vectors_order() -> TestResult {
    if VEC_DIVIDE_ERROR != 0 {
        return TestResult::Fail;
    }
    if VEC_DEBUG != 1 {
        return TestResult::Fail;
    }
    if VEC_NMI != 2 {
        return TestResult::Fail;
    }
    if VEC_BREAKPOINT != 3 {
        return TestResult::Fail;
    }
    if VEC_OVERFLOW != 4 {
        return TestResult::Fail;
    }
    if VEC_BOUND_RANGE != 5 {
        return TestResult::Fail;
    }
    if VEC_INVALID_OPCODE != 6 {
        return TestResult::Fail;
    }
    if VEC_DEVICE_NOT_AVAILABLE != 7 {
        return TestResult::Fail;
    }
    if VEC_DOUBLE_FAULT != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_vectors_high() -> TestResult {
    if VEC_COPROCESSOR_SEGMENT != 9 {
        return TestResult::Fail;
    }
    if VEC_INVALID_TSS != 10 {
        return TestResult::Fail;
    }
    if VEC_SEGMENT_NOT_PRESENT != 11 {
        return TestResult::Fail;
    }
    if VEC_STACK_SEGMENT != 12 {
        return TestResult::Fail;
    }
    if VEC_GENERAL_PROTECTION != 13 {
        return TestResult::Fail;
    }
    if VEC_PAGE_FAULT != 14 {
        return TestResult::Fail;
    }
    if VEC_X87_FP != 16 {
        return TestResult::Fail;
    }
    if VEC_ALIGNMENT_CHECK != 17 {
        return TestResult::Fail;
    }
    if VEC_MACHINE_CHECK != 18 {
        return TestResult::Fail;
    }
    if VEC_SIMD_FP != 19 {
        return TestResult::Fail;
    }
    if VEC_VIRTUALIZATION != 20 {
        return TestResult::Fail;
    }
    if VEC_CONTROL_PROTECTION != 21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_base() -> TestResult {
    if IRQ_BASE != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_base_after_exceptions() -> TestResult {
    if (IRQ_BASE as usize) <= (VEC_CONTROL_PROTECTION as usize) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ist_indices() -> TestResult {
    if IST_DOUBLE_FAULT != 1 {
        return TestResult::Fail;
    }
    if IST_NMI != 2 {
        return TestResult::Fail;
    }
    if IST_MACHINE_CHECK != 3 {
        return TestResult::Fail;
    }
    if IST_DEBUG != 4 {
        return TestResult::Fail;
    }
    if IST_PAGE_FAULT != 5 {
        return TestResult::Fail;
    }
    if IST_GP != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ist_indices_valid_range() -> TestResult {
    if IST_DOUBLE_FAULT > 7 {
        return TestResult::Fail;
    }
    if IST_NMI > 7 {
        return TestResult::Fail;
    }
    if IST_MACHINE_CHECK > 7 {
        return TestResult::Fail;
    }
    if IST_DEBUG > 7 {
        return TestResult::Fail;
    }
    if IST_PAGE_FAULT > 7 {
        return TestResult::Fail;
    }
    if IST_GP > 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ist_indices_nonzero() -> TestResult {
    if IST_DOUBLE_FAULT == 0 {
        return TestResult::Fail;
    }
    if IST_NMI == 0 {
        return TestResult::Fail;
    }
    if IST_MACHINE_CHECK == 0 {
        return TestResult::Fail;
    }
    if IST_DEBUG == 0 {
        return TestResult::Fail;
    }
    if IST_PAGE_FAULT == 0 {
        return TestResult::Fail;
    }
    if IST_GP == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exceptions_below_irq_base() -> TestResult {
    if VEC_DIVIDE_ERROR >= IRQ_BASE {
        return TestResult::Fail;
    }
    if VEC_DOUBLE_FAULT >= IRQ_BASE {
        return TestResult::Fail;
    }
    if VEC_PAGE_FAULT >= IRQ_BASE {
        return TestResult::Fail;
    }
    if VEC_GENERAL_PROTECTION >= IRQ_BASE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_exceptions_unique() -> TestResult {
    let exceptions = [
        VEC_DIVIDE_ERROR,
        VEC_DEBUG,
        VEC_NMI,
        VEC_BREAKPOINT,
        VEC_OVERFLOW,
        VEC_BOUND_RANGE,
        VEC_INVALID_OPCODE,
        VEC_DEVICE_NOT_AVAILABLE,
        VEC_DOUBLE_FAULT,
        VEC_COPROCESSOR_SEGMENT,
        VEC_INVALID_TSS,
        VEC_SEGMENT_NOT_PRESENT,
        VEC_STACK_SEGMENT,
        VEC_GENERAL_PROTECTION,
        VEC_PAGE_FAULT,
        VEC_X87_FP,
        VEC_ALIGNMENT_CHECK,
        VEC_MACHINE_CHECK,
        VEC_SIMD_FP,
        VEC_VIRTUALIZATION,
        VEC_CONTROL_PROTECTION,
    ];
    for i in 0..exceptions.len() {
        for j in (i + 1)..exceptions.len() {
            if exceptions[i] == exceptions[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_idt_size_fits_256_entries() -> TestResult {
    if IDT_ENTRIES > 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
