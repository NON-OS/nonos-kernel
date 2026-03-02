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

use super::types::{InterruptFrame, ExecContext};

const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;

pub fn enable_smep() {
    // SAFETY: Reading and writing CR4 to enable SMEP
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        if cr4 & CR4_SMEP == 0 {
            cr4 |= CR4_SMEP;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        }
    }
}

pub fn enable_smap() {
    // SAFETY: Reading and writing CR4 to enable SMAP
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        if cr4 & CR4_SMAP == 0 {
            cr4 |= CR4_SMAP;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        }
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn jump_to_usermode(entry: u64, stack: u64, arg: u64) -> ! {
    core::arch::naked_asm!(
        // Apply side-channel mitigations before entering user mode
        // (RSB stuffing, etc. - call our mitigation function first)

        // Set up data segments for user mode
        "mov ax, 0x23",      // USER_DS
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",

        // Push IRET frame in reverse order:
        // SS, RSP, RFLAGS, CS, RIP
        "push 0x23",         // SS (USER_DS)
        "push rsi",          // RSP (stack - second argument)
        "push 0x202",        // RFLAGS (IF set)
        "push 0x1B",         // CS (USER_CS)
        "push rdi",          // RIP (entry - first argument)

        // Set up argument in RDI for user program
        "mov rdi, rdx",      // arg (third argument) -> RDI

        // Clear other registers to prevent info leaks
        "xor rax, rax",
        "xor rbx, rbx",
        "xor rcx, rcx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",

        // IRET to user mode
        "iretq",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn return_to_usermode(frame: *const InterruptFrame) -> ! {
    core::arch::naked_asm!(
        // Load the interrupt frame address
        "mov rsp, rdi",

        // Set up data segments
        "mov ax, 0x23",
        "mov ds, ax",
        "mov es, ax",

        // IRET pops: RIP, CS, RFLAGS, RSP, SS
        "iretq",
    );
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn sysret_to_usermode(rip: u64, rsp: u64, rflags: u64, retval: u64) -> ! {
    core::arch::naked_asm!(
        // RDI = rip, RSI = rsp, RDX = rflags, RCX = retval

        // Validate RIP is canonical (prevent SYSRET vulnerability)
        // Non-canonical addresses in RCX can cause GP fault in kernel mode
        "mov rax, rdi",
        "shr rax, 47",
        "cmp rax, 0",
        "je 2f",
        "cmp rax, 0x1FFFF",
        "jne 1f",
        "2:",

        // Set return value in RAX
        "mov rax, rcx",

        // Set up for SYSRET
        "mov rcx, rdi",      // RCX = return RIP
        "mov r11, rdx",      // R11 = return RFLAGS
        "mov rsp, rsi",      // RSP = user stack

        // Clear other registers
        "xor rbx, rbx",
        "xor rdx, rdx",
        "xor rsi, rsi",
        "xor rdi, rdi",
        "xor rbp, rbp",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r12, r12",
        "xor r13, r13",
        "xor r14, r14",
        "xor r15, r15",

        // SWAPGS and return
        "swapgs",
        "sysretq",

        // Error path - use IRET instead
        "1:",
        "ud2",               // Should never happen with proper validation
    );
}

pub fn exec_process(ctx: &ExecContext) -> ! {
    // Ensure interrupts are disabled during setup
    x86_64::instructions::interrupts::disable();

    // Switch to process page table
    // SAFETY: ctx.cr3 contains a valid page table physical address that was set up
    // by the process loader. Writing CR3 switches to the process's address space.
    // Interrupts are disabled above to prevent race conditions during the switch.
    // The nostack option is correct as no additional stack space is used.
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) ctx.cr3,
            options(nostack)
        );
    }

    // Apply side-channel mitigations
    crate::security::spectre_mitigations::kernel_exit_mitigations();

    // Jump to user mode
    // SAFETY: The preconditions for jump_to_usermode are satisfied:
    // - ctx.entry is a valid user-mode address (validated by ELF loader)
    // - ctx.stack is a valid user-mode stack address (allocated for the process)
    // - The process page tables are now active (CR3 was set above)
    // - Interrupts are disabled (done above)
    unsafe {
        jump_to_usermode(ctx.entry, ctx.stack, ctx.argc);
    }
}
