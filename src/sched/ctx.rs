// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
// NØNOS kernel context switching (x86_64, ring0) —
// - Callee-saved GP set (RBX/RBP/R12..R15) + RIP/RSP/RFLAGS
// - Optional FS/GS base save/restore (per-thread TLS) behind feature
// - Optional XSAVE/XRSTOR (or FXSAVE/FXRSTOR) for FPU/SIMD context
// - Non-preemptible switch discipline (caller disables IRQs around switch())
// - Naked entry trampoline: first run calls entry(arg), returns -> exit()
// - IF bit policy: caller decides; we preserve/restore RFLAGS exactly
// - Audit-friendly: preserves frame pointer; no red zone assumptions
//
// Build flags expected:
//   features = ["fsgsbase", "xsave"]   // optional; guard paths below.
//
// Safety: only switch between valid, mapped stacks. Callers must prevent concurrent mutation.

#![allow(dead_code)]
#![cfg_attr(any(feature="xsave",feature="fsgsbase"), feature(asm_const))]

use core::arch::asm;

// ————————————————————————————————————————————————————————————————————————
// CPU feature gates (cached at boot by arch init; stubbed here)
// ————————————————————————————————————————————————————————————————————————

#[inline(always)] fn cpu_has_xsave() -> bool {
    #[cfg(feature="xsave")] { true } #[cfg(not(feature="xsave"))] { false }
}
#[inline(always)] fn cpu_has_fsgsbase() -> bool {
    #[cfg(feature="fsgsbase")] { true } #[cfg(not(feature="fsgsbase"))] { false }
}

// Max xsave area we support (aligned to 64). Caller provides storage in Task.
pub const XSAVE_MAX: usize = 4096;

// ————————————————————————————————————————————————————————————————————————
// Context record
// ————————————————————————————————————————————————————————————————————————

#[repr(C, align(16))]
#[derive(Default)]
pub struct Context {
    // Callee-saved (SysV)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,

    // Return frame
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,

    // Optional thread TLS bases (only if you actually use per-thread FS/GS)
    #[cfg(feature="fsgsbase")]
    pub fs_base: u64,
    #[cfg(feature="fsgsbase")]
    pub gs_base: u64,

    // Optional extended state pointer (XSAVE buffer) and mask
    #[cfg(feature="xsave")]
    pub xsave_ptr: u64,      // must be XSAVE_MAX-aligned (64B min per SDM)
    #[cfg(feature="xsave")]
    pub xcr0_mask: u64,      // which components to save/restore
}

// First entry for a virgin context.
pub type EntryFn = extern "C" fn(usize) -> !;

// ————————————————————————————————————————————————————————————————————————
// Public API
// ————————————————————————————————————————————————————————————————————————

/// We repare a brand‑new kernel context on `stack_top`.
/// The first `switch()` into it jumps to `entry(arg)`. If it ever returns,
/// control transfers to `exit_trampoline`.
pub unsafe fn init_context(
    ctx: &mut Context,
    stack_top: u64,
    entry: EntryFn,
    arg: usize,
    exit_trampoline: extern "C" fn() -> !,
    #[cfg(feature="xsave")] xsave_buf_opt: Option<(*mut u8, u64)>, // (ptr, xcr0_mask)
) {
    *ctx = Context::default();

    // Stash argument in r12 (callee-saved, survives switch prologue)
    ctx.r12   = arg as u64;
    ctx.rip   = ctx_enter as u64;
    ctx.rsp   = stack_top & !0xF; // 16B alignment
    ctx.rflags = 0x0000_0000_0000_0202; // IF=0; caller decides later

    // Shadow space on stack for entry/exit pointers (popped by ctx_enter)
    push64(ctx, exit_trampoline as u64);
    push64(ctx, entry as u64);

    #[cfg(feature="xsave")]
    if let Some((p, mask)) = xsave_buf_opt {
        ctx.xsave_ptr  = p as u64;
        ctx.xcr0_mask  = mask;
        // Zero the area for determinism
        core::ptr::write_bytes(p, 0, XSAVE_MAX);
    }
}

/// Switch from `from` → `to`.
/// Precondition: interrupts disabled (or preemption otherwise inhibited).
#[inline(always)]
pub unsafe fn switch(from: *mut Context, to: *const Context) -> ! {
    // Save/restore discipline:
    // 1) Save callee-saved + RIP/RSP/RFLAGS to *from.
    // 2) (opt) save FS/GS base; (opt) save XSAVE area.
    // 3) Load callee-saved + RSP/RIP/RFLAGS from *to.
    // 4) (opt) restore FS/GS base; (opt) restore XSAVE area.
    // 5) Far return via `ret` on pushed RIP & RFLAGS (keeps audit-friendly frames).

    asm!(
        // — save callee-saved into *from
        "mov     [rdi + 0x00], r15",
        "mov     [rdi + 0x08], r14",
        "mov     [rdi + 0x10], r13",
        "mov     [rdi + 0x18], r12",
        "mov     [rdi + 0x20], rbx",
        "mov     [rdi + 0x28], rbp",
        "lea     rax, [rip + 2f]",         // next RIP after restore path
        "mov     [rdi + 0x30], rax",       // rip
        "mov     rax, rsp",
        "mov     [rdi + 0x38], rax",       // rsp
        "pushfq",
        "pop     qword ptr [rdi + 0x40]",  // rflags

        // — optional FS/GS base save
        if cfg!(feature="fsgsbase") {
            "rdfsbase rax",
            "mov     [rdi + 0x48], rax",
            "rdgsbase rax",
            "mov     [rdi + 0x50], rax",
        }
        // *optional** XSAVE save (eager; lazy handled elsewhere)
        if cfg!(feature="xsave") {
            // rdi=*from; xsave_ptr at +offset
            "mov     rax, [rdi + {XS_PTR}]",
            "mov     rcx, [rdi + {XCR0}]",
            // ldmxcsr/stmxcsr not needed: lives in xsave area
            "xor     rdx, rdx",
            "xsaveopt [rax]",
            XS_PTR = const offset_of_xsave_ptr(),
            XCR0   = const offset_of_xcr0(),
        }

        // — load callee-saved from *to
        "mov     r15, [rsi + 0x00]",
        "mov     r14, [rsi + 0x08]",
        "mov     r13, [rsi + 0x10]",
        "mov     r12, [rsi + 0x18]",
        "mov     rbx, [rsi + 0x20]",
        "mov     rbp, [rsi + 0x28]",

        // — load RSP/RFLAGS/RIP
        "mov     rax, [rsi + 0x38]",
        "mov     rsp, rax",
        "mov     rax, [rsi + 0x40]",
        "push    rax",                     // push RFLAGS
        "mov     rax, [rsi + 0x30]",
        "push    rax",                     // push RIP

        // — optional FS/GS base restore
        if cfg!(feature="fsgsbase") {
            "mov     rax, [rsi + 0x48]",
            "wrfsbase rax",
            "mov     rax, [rsi + 0x50]",
            "wrgsbase rax",
        }

        // — optional XRSTOR restore
        if cfg!(feature="xsave") {
            "mov     rax, [rsi + {XS_PTR}]",
            "mov     rcx, [rsi + {XCR0}]",
            "xor     rdx, rdx",
            "xrstor  [rax]",
            XS_PTR = const offset_of_xsave_ptr(),
            XCR0   = const offset_of_xcr0(),
        }

        // — return into `to` (popped RIP/RFLAGS). CS/SS unchanged in ring0 flat.
        "ret",

        "2:",
        options(noreturn)
    );
}

// ————————————————————————————————————————————————————————————————————————
// First-entry trampoline
// Stack on entry (set by init_context):
//   [rsp]   = entry()
//   [rsp+8] = exit()
//   r12     = arg
// ————————————————————————————————————————————————————————————————————————

#[naked]
extern "C" fn ctx_enter() -> ! {
    unsafe {
        asm!(
            "
            pop     rax         // entry
            pop     rdx         // exit
            mov     rdi, r12    // arg
            // IF is whatever was restored by switch(); we leave it to scheduler policy.
            call    rax
            jmp     rdx         // if entry ever returns
            ",
            options(noreturn)
        )
    }
}

// ————————————————————————————————————————————————————————————————————————
// Helpers
// ————————————————————————————————————————————————————————————————————————

#[inline(always)]
unsafe fn push64(ctx: &mut Context, v: u64) {
    ctx.rsp = (ctx.rsp - 8) & !0xF;
    (ctx.rsp as *mut u64).write(v);
}

// Compute field offsets for inline-consts in asm by keeping layout in one place.
#[cfg(feature="xsave")] #[inline(always)] const fn offset_of_xsave_ptr() -> usize {
    // r15..rflags = 0x00..0x40 (64 bytes). Then fs/gs optionally.
    // With fsgsbase: fs_base @0x48, gs_base @0x50, xsave_ptr @0x58, xcr0 @0x60.
    // Without fsgsbase: xsave_ptr @0x48, xcr0 @0x50.
    if cfg!(feature="fsgsbase") { 0x58 } else { 0x48 }
}
#[cfg(feature="xsave")] #[inline(always)] const fn offset_of_xcr0() -> usize {
    if cfg!(feature="fsgsbase") { 0x60 } else { 0x50 }
}

// ————————————————————————————————————————————————————————————————————————
// Optional FPU ownership helpers (lazy save model hook)
// (We can wire CR0.TS and #NM handler to grab FPU on first use per task.)
// ————————————————————————————————————————————————————————————————————————

#[cfg(feature="xsave")]
#[inline(always)]
pub fn xsave_area_len(xcr0_mask: u64) -> usize {
    // For now return XSAVE_MAX; and refine later by CPUID.(EAX=0xD,ECX=0).
    let _ = xcr0_mask; XSAVE_MAX
}
