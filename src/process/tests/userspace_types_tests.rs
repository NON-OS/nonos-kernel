// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::process::userspace::types::{
    ThreadState, BlockReason, FpuState, InterruptFrame, UserContext, ExecContext,
    USER_CS, USER_DS, KERNEL_CS, KERNEL_DS, USER_RFLAGS,
    USER_STACK_SIZE, KERNEL_STACK_SIZE, USER_STACK_BASE, USER_HEAP_START, USER_CODE_START,
};

#[test]
fn test_user_cs_constant() {
    assert_eq!(USER_CS, 0x1B);
}

#[test]
fn test_user_ds_constant() {
    assert_eq!(USER_DS, 0x23);
}

#[test]
fn test_kernel_cs_constant() {
    assert_eq!(KERNEL_CS, 0x08);
}

#[test]
fn test_kernel_ds_constant() {
    assert_eq!(KERNEL_DS, 0x10);
}

#[test]
fn test_user_rflags_constant() {
    assert_eq!(USER_RFLAGS, 0x202);
}

#[test]
fn test_user_stack_size_constant() {
    assert_eq!(USER_STACK_SIZE, 2 * 1024 * 1024);
}

#[test]
fn test_kernel_stack_size_constant() {
    assert_eq!(KERNEL_STACK_SIZE, 16 * 1024);
}

#[test]
fn test_user_stack_base_constant() {
    assert_eq!(USER_STACK_BASE, 0x0000_7FFF_FFFF_0000);
}

#[test]
fn test_user_heap_start_constant() {
    assert_eq!(USER_HEAP_START, 0x0000_0001_0000_0000);
}

#[test]
fn test_user_code_start_constant() {
    assert_eq!(USER_CODE_START, 0x0000_0000_0040_0000);
}

#[test]
fn test_segment_selectors_ring_3() {
    assert_eq!(USER_CS & 0x3, 3);
    assert_eq!(USER_DS & 0x3, 3);
}

#[test]
fn test_segment_selectors_ring_0() {
    assert_eq!(KERNEL_CS & 0x3, 0);
    assert_eq!(KERNEL_DS & 0x3, 0);
}

#[test]
fn test_thread_state_ready() {
    let state = ThreadState::Ready;
    assert_eq!(state, ThreadState::Ready);
    assert_eq!(state as u8, 0);
}

#[test]
fn test_thread_state_running() {
    let state = ThreadState::Running;
    assert_eq!(state, ThreadState::Running);
    assert_eq!(state as u8, 1);
}

#[test]
fn test_thread_state_blocked() {
    let state = ThreadState::Blocked;
    assert_eq!(state, ThreadState::Blocked);
    assert_eq!(state as u8, 2);
}

#[test]
fn test_thread_state_sleeping() {
    let state = ThreadState::Sleeping;
    assert_eq!(state, ThreadState::Sleeping);
    assert_eq!(state as u8, 3);
}

#[test]
fn test_thread_state_zombie() {
    let state = ThreadState::Zombie;
    assert_eq!(state, ThreadState::Zombie);
    assert_eq!(state as u8, 4);
}

#[test]
fn test_thread_state_stopped() {
    let state = ThreadState::Stopped;
    assert_eq!(state, ThreadState::Stopped);
    assert_eq!(state as u8, 5);
}

#[test]
fn test_thread_state_equality() {
    assert_eq!(ThreadState::Ready, ThreadState::Ready);
    assert_ne!(ThreadState::Ready, ThreadState::Running);
}

#[test]
fn test_thread_state_clone() {
    let state = ThreadState::Blocked;
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

#[test]
fn test_thread_state_copy() {
    let state = ThreadState::Running;
    let copied = state;
    assert_eq!(state, copied);
}

#[test]
fn test_block_reason_io() {
    let reason = BlockReason::Io;
    assert_eq!(reason, BlockReason::Io);
}

#[test]
fn test_block_reason_lock() {
    let reason = BlockReason::Lock;
    assert_eq!(reason, BlockReason::Lock);
}

#[test]
fn test_block_reason_futex() {
    let reason = BlockReason::Futex(0x12345678);
    if let BlockReason::Futex(addr) = reason {
        assert_eq!(addr, 0x12345678);
    } else {
        panic!("Expected Futex variant");
    }
}

#[test]
fn test_block_reason_wait() {
    let reason = BlockReason::Wait;
    assert_eq!(reason, BlockReason::Wait);
}

#[test]
fn test_block_reason_signal() {
    let reason = BlockReason::Signal;
    assert_eq!(reason, BlockReason::Signal);
}

#[test]
fn test_block_reason_ipc() {
    let reason = BlockReason::Ipc;
    assert_eq!(reason, BlockReason::Ipc);
}

#[test]
fn test_block_reason_futex_equality() {
    let r1 = BlockReason::Futex(100);
    let r2 = BlockReason::Futex(100);
    let r3 = BlockReason::Futex(200);
    assert_eq!(r1, r2);
    assert_ne!(r1, r3);
}

#[test]
fn test_block_reason_different_variants() {
    assert_ne!(BlockReason::Io, BlockReason::Lock);
    assert_ne!(BlockReason::Wait, BlockReason::Signal);
}

#[test]
fn test_block_reason_clone() {
    let reason = BlockReason::Futex(42);
    let cloned = reason.clone();
    assert_eq!(reason, cloned);
}

#[test]
fn test_fpu_state_default() {
    let fpu = FpuState::default();
    assert_eq!(fpu.data.len(), 1024);
    assert!(fpu.data.iter().all(|&b| b == 0));
}

#[test]
fn test_fpu_state_size() {
    assert_eq!(core::mem::size_of::<FpuState>(), 1024);
}

#[test]
fn test_fpu_state_alignment() {
    assert_eq!(core::mem::align_of::<FpuState>(), 64);
}

#[test]
fn test_interrupt_frame_for_user_entry() {
    let frame = InterruptFrame::for_user_entry(0x401000, 0x7FFFFF000);
    assert_eq!(frame.rip, 0x401000);
    assert_eq!(frame.cs, USER_CS as u64);
    assert_eq!(frame.rflags, USER_RFLAGS);
    assert_eq!(frame.rsp, 0x7FFFFF000);
    assert_eq!(frame.ss, USER_DS as u64);
}

#[test]
fn test_interrupt_frame_clone() {
    let frame1 = InterruptFrame::for_user_entry(0x401000, 0x7FFFFF000);
    let frame2 = frame1.clone();
    assert_eq!(frame1.rip, frame2.rip);
    assert_eq!(frame1.cs, frame2.cs);
    assert_eq!(frame1.rflags, frame2.rflags);
    assert_eq!(frame1.rsp, frame2.rsp);
    assert_eq!(frame1.ss, frame2.ss);
}

#[test]
fn test_interrupt_frame_copy() {
    let frame1 = InterruptFrame::for_user_entry(0x500000, 0x8000000);
    let frame2 = frame1;
    assert_eq!(frame1.rip, frame2.rip);
}

#[test]
fn test_interrupt_frame_size() {
    assert_eq!(core::mem::size_of::<InterruptFrame>(), 40);
}

#[test]
fn test_user_context_default() {
    let ctx = UserContext::default();
    assert_eq!(ctx.rax, 0);
    assert_eq!(ctx.rbx, 0);
    assert_eq!(ctx.rcx, 0);
    assert_eq!(ctx.rdx, 0);
    assert_eq!(ctx.rsi, 0);
    assert_eq!(ctx.rdi, 0);
    assert_eq!(ctx.rbp, 0);
    assert_eq!(ctx.rsp, 0);
    assert_eq!(ctx.r8, 0);
    assert_eq!(ctx.r9, 0);
    assert_eq!(ctx.r10, 0);
    assert_eq!(ctx.r11, 0);
    assert_eq!(ctx.r12, 0);
    assert_eq!(ctx.r13, 0);
    assert_eq!(ctx.r14, 0);
    assert_eq!(ctx.r15, 0);
    assert_eq!(ctx.rip, 0);
    assert_eq!(ctx.cs, 0);
    assert_eq!(ctx.rflags, 0);
    assert_eq!(ctx.ss, 0);
    assert_eq!(ctx.fs_base, 0);
    assert_eq!(ctx.gs_base, 0);
}

#[test]
fn test_user_context_size() {
    assert_eq!(core::mem::size_of::<UserContext>(), 22 * 8);
}

#[test]
fn test_user_context_clone() {
    let mut ctx1 = UserContext::default();
    ctx1.rax = 42;
    ctx1.rip = 0x401000;
    ctx1.rsp = 0x7FFFFF000;
    let ctx2 = ctx1.clone();
    assert_eq!(ctx1.rax, ctx2.rax);
    assert_eq!(ctx1.rip, ctx2.rip);
    assert_eq!(ctx1.rsp, ctx2.rsp);
}

#[test]
fn test_user_context_copy() {
    let mut ctx1 = UserContext::default();
    ctx1.rdi = 100;
    let ctx2 = ctx1;
    assert_eq!(ctx1.rdi, ctx2.rdi);
}

#[test]
fn test_exec_context_fields() {
    let ctx = ExecContext {
        entry: 0x401000,
        stack: 0x7FFFFF000,
        pid: 1234,
        tid: 5678,
        cr3: 0x100000,
        argc: 3,
        argv: 0x7FFFFFE00,
        envp: 0x7FFFFFE80,
    };
    assert_eq!(ctx.entry, 0x401000);
    assert_eq!(ctx.stack, 0x7FFFFF000);
    assert_eq!(ctx.pid, 1234);
    assert_eq!(ctx.tid, 5678);
    assert_eq!(ctx.cr3, 0x100000);
    assert_eq!(ctx.argc, 3);
    assert_eq!(ctx.argv, 0x7FFFFFE00);
    assert_eq!(ctx.envp, 0x7FFFFFE80);
}

#[test]
fn test_exec_context_size() {
    assert_eq!(core::mem::size_of::<ExecContext>(), 8 * 8);
}

#[test]
fn test_user_space_addresses_valid() {
    assert!(USER_STACK_BASE < 0x0000_8000_0000_0000);
    assert!(USER_HEAP_START < 0x0000_8000_0000_0000);
    assert!(USER_CODE_START < 0x0000_8000_0000_0000);
}

#[test]
fn test_user_space_layout_order() {
    assert!(USER_CODE_START < USER_HEAP_START);
    assert!(USER_HEAP_START < USER_STACK_BASE);
}

#[test]
fn test_user_rflags_interrupt_enabled() {
    assert!((USER_RFLAGS & 0x200) != 0);
}

#[test]
fn test_user_rflags_reserved_bit_set() {
    assert!((USER_RFLAGS & 0x2) != 0);
}

#[test]
fn test_stack_sizes_power_of_two() {
    assert!((USER_STACK_SIZE & (USER_STACK_SIZE - 1)) == 0);
    assert!((KERNEL_STACK_SIZE & (KERNEL_STACK_SIZE - 1)) == 0);
}

#[test]
fn test_kernel_stack_smaller_than_user() {
    assert!(KERNEL_STACK_SIZE < USER_STACK_SIZE);
}

#[test]
fn test_thread_state_all_variants() {
    let states = [
        ThreadState::Ready,
        ThreadState::Running,
        ThreadState::Blocked,
        ThreadState::Sleeping,
        ThreadState::Zombie,
        ThreadState::Stopped,
    ];
    for (i, state) in states.iter().enumerate() {
        assert_eq!(*state as u8, i as u8);
    }
}

#[test]
fn test_block_reason_all_simple_variants() {
    let reasons = [
        BlockReason::Io,
        BlockReason::Lock,
        BlockReason::Wait,
        BlockReason::Signal,
        BlockReason::Ipc,
    ];
    for reason in reasons {
        let cloned = reason.clone();
        assert_eq!(reason, cloned);
    }
}

#[test]
fn test_interrupt_frame_fields() {
    let frame = InterruptFrame {
        rip: 0xDEADBEEF,
        cs: 0x1B,
        rflags: 0x202,
        rsp: 0xCAFEBABE,
        ss: 0x23,
    };
    assert_eq!(frame.rip, 0xDEADBEEF);
    assert_eq!(frame.cs, 0x1B);
    assert_eq!(frame.rflags, 0x202);
    assert_eq!(frame.rsp, 0xCAFEBABE);
    assert_eq!(frame.ss, 0x23);
}

#[test]
fn test_user_context_all_registers() {
    let ctx = UserContext {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        r11: 11,
        r10: 10,
        r9: 9,
        r8: 8,
        rdi: 7,
        rsi: 6,
        rbp: 5,
        rbx: 4,
        rdx: 3,
        rcx: 2,
        rax: 1,
        rip: 0x400000,
        cs: 0x1B,
        rflags: 0x202,
        rsp: 0x7FFFFFF0,
        ss: 0x23,
        fs_base: 0x100,
        gs_base: 0x200,
    };
    assert_eq!(ctx.r15, 15);
    assert_eq!(ctx.r8, 8);
    assert_eq!(ctx.rax, 1);
    assert_eq!(ctx.fs_base, 0x100);
    assert_eq!(ctx.gs_base, 0x200);
}

#[test]
fn test_segment_selector_gdt_index() {
    assert_eq!((USER_CS >> 3) & 0x1FFF, 3);
    assert_eq!((USER_DS >> 3) & 0x1FFF, 4);
    assert_eq!((KERNEL_CS >> 3) & 0x1FFF, 1);
    assert_eq!((KERNEL_DS >> 3) & 0x1FFF, 2);
}

#[test]
fn test_user_context_debug() {
    let ctx = UserContext::default();
    let debug_str = alloc::format!("{:?}", ctx);
    assert!(debug_str.contains("UserContext"));
}

#[test]
fn test_interrupt_frame_debug() {
    let frame = InterruptFrame::for_user_entry(0x401000, 0x7FFFFF000);
    let debug_str = alloc::format!("{:?}", frame);
    assert!(debug_str.contains("InterruptFrame"));
}

#[test]
fn test_thread_state_debug() {
    let state = ThreadState::Running;
    let debug_str = alloc::format!("{:?}", state);
    assert!(debug_str.contains("Running"));
}

#[test]
fn test_block_reason_debug() {
    let reason = BlockReason::Futex(0x1000);
    let debug_str = alloc::format!("{:?}", reason);
    assert!(debug_str.contains("Futex"));
}

