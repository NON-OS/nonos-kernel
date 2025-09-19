//! Production Context Switching Implementation
//!
//! Ultra-advanced context switching with security, performance optimization,
//! and full x86_64 state management

use core::arch::asm;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::virt::{VmFlags, map4k_at};
use crate::memory::phys::{alloc, AllocFlags};
use alloc::format;

/// Complete CPU context with extended state
#[repr(C, align(16))]
#[derive(Debug, Clone)]
pub struct Context {
    // General purpose registers
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    
    // Control registers
    pub rip: u64,
    pub rflags: u64,
    pub cr3: u64,
    
    // Segment selectors
    pub cs: u16, pub ds: u16, pub es: u16, pub fs: u16, pub gs: u16, pub ss: u16,
    
    // Extended state
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    
    // FPU/SSE/AVX state pointer (512+ bytes, dynamically allocated)
    pub fpu_state: Option<VirtAddr>,
    
    // Security context
    pub security_token: u64,
    pub capability_mask: u64,
}

impl Context {
    /// Create new kernel task context
    pub fn new_kernel_task(entry: VirtAddr, stack: VirtAddr, cr3: PhysAddr) -> Self {
        Context {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, 
            rsp: stack.as_u64(),
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: entry.as_u64(),
            rflags: 0x202, // IF=1, reserved bit 1=1
            cr3: cr3.as_u64(),
            cs: 0x08, ds: 0x10, es: 0x10, fs: 0x10, gs: 0x10, ss: 0x10, // Kernel segments
            fs_base: 0, gs_base: 0, kernel_gs_base: 0,
            fpu_state: None,
            security_token: 0,
            capability_mask: 0xFFFFFFFFFFFFFFFF, // Kernel has all capabilities
        }
    }
    
    /// Create new user task context  
    pub fn new_user_task(entry: VirtAddr, stack: VirtAddr, cr3: PhysAddr) -> Self {
        Context {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0,
            rsp: stack.as_u64(),
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: entry.as_u64(),
            rflags: 0x202, // IF=1, reserved bit 1=1
            cr3: cr3.as_u64(),
            cs: 0x1B, ds: 0x23, es: 0x23, fs: 0x23, gs: 0x23, ss: 0x23, // User segments
            fs_base: 0, gs_base: 0, kernel_gs_base: 0,
            fpu_state: None,
            security_token: 0,
            capability_mask: 0x0000000000000FFF, // Limited user capabilities
        }
    }
    
    /// Allocate and initialize FPU state
    pub fn init_fpu_state(&mut self) -> Result<(), &'static str> {
        // Allocate page for FPU state (XSAVE area can be up to 4KB)
        if let Some(frame) = alloc(AllocFlags::ZEROED) {
            let fpu_addr = VirtAddr::new(0xFFFF_8800_1000_0000 + frame.0); // Map in kernel heap
            if map4k_at(fpu_addr, PhysAddr::new(frame.0), VmFlags::RW | VmFlags::NX).is_ok() {
                self.fpu_state = Some(fpu_addr);
                
                // Initialize with default FPU state
                unsafe {
                    let fpu_ptr = fpu_addr.as_mut_ptr::<[u8; 512]>();
                    // Set default x87 control word, MXCSR, etc.
                    (*fpu_ptr)[0] = 0x37; (*fpu_ptr)[1] = 0x1F; // x87 CW = 0x1F37
                    (*fpu_ptr)[24] = 0x80; (*fpu_ptr)[25] = 0x1F; // MXCSR = 0x1F80
                }
                Ok(())
            } else {
                Err("Failed to map FPU state page")
            }
        } else {
            Err("Failed to allocate FPU state")
        }
    }
}

/// Ultra-secure context switch with complete state save/restore
#[naked]
pub unsafe extern "C" fn switch_context_secure(
    old_ctx: *mut Context, 
    new_ctx: *const Context
) -> ! {
    asm!(
        // === SAVE OLD CONTEXT ===
        // Save general purpose registers
        "mov [rdi + 0x00], rax", "mov [rdi + 0x08], rbx", "mov [rdi + 0x10], rcx", "mov [rdi + 0x18], rdx",
        "mov [rdi + 0x20], rsi", "mov [rdi + 0x28], rdi", "mov [rdi + 0x30], rbp", "mov [rdi + 0x38], rsp",
        "mov [rdi + 0x40], r8",  "mov [rdi + 0x48], r9",  "mov [rdi + 0x50], r10", "mov [rdi + 0x58], r11",
        "mov [rdi + 0x60], r12", "mov [rdi + 0x68], r13", "mov [rdi + 0x70], r14", "mov [rdi + 0x78], r15",
        
        // Save control registers
        "lea rax, [rip + 2f]", "mov [rdi + 0x80], rax", // Save return RIP
        "pushf", "pop rax", "mov [rdi + 0x88], rax",     // Save RFLAGS
        "mov rax, cr3", "mov [rdi + 0x90], rax",         // Save CR3
        
        // Save segment registers
        "mov ax, cs", "mov [rdi + 0x98], ax",
        "mov ax, ds", "mov [rdi + 0x9A], ax", 
        "mov ax, es", "mov [rdi + 0x9C], ax",
        "mov ax, fs", "mov [rdi + 0x9E], ax",
        "mov ax, gs", "mov [rdi + 0xA0], ax",
        "mov ax, ss", "mov [rdi + 0xA2], ax",
        
        // Save extended registers
        "rdgsbase rax", "mov [rdi + 0xB0], rax", // GS.BASE
        "swapgs", "rdgsbase rax", "swapgs", "mov [rdi + 0xB8], rax", // KERNEL_GS_BASE
        
        // Save FPU state if present
        "mov rax, [rdi + 0xD0]", // fpu_state pointer
        "test rax, rax",
        "jz 1f",
        "fxsave [rax]", // Save FPU/SSE state
        "1:",
        
        // === LOAD NEW CONTEXT ===
        // Load FPU state first
        "mov rax, [rsi + 0xD0]", // new fpu_state pointer  
        "test rax, rax",
        "jz 3f",
        "fxrstor [rax]", // Restore FPU/SSE state
        "3:",
        
        // Load extended registers
        "mov rax, [rsi + 0xB0]", "wrgsbase rax", // GS.BASE
        "swapgs", "mov rax, [rsi + 0xB8]", "wrgsbase rax", "swapgs", // KERNEL_GS_BASE
        
        // Load CR3 (page table switch)
        "mov rax, [rsi + 0x90]", "mov cr3, rax",
        
        // Load segment registers (be careful with this)
        "mov ax, [rsi + 0x9A]", "mov ds, ax",
        "mov ax, [rsi + 0x9C]", "mov es, ax", 
        "mov ax, [rsi + 0x9E]", "mov fs, ax",
        "mov ax, [rsi + 0xA0]", "mov gs, ax",
        
        // Load RFLAGS
        "mov rax, [rsi + 0x88]", "push rax", "popf",
        
        // Load general purpose registers
        "mov rax, [rsi + 0x00]", "mov rbx, [rsi + 0x08]", "mov rcx, [rsi + 0x10]", "mov rdx, [rsi + 0x18]",
        "mov rbp, [rsi + 0x30]", "mov rsp, [rsi + 0x38]",
        "mov r8,  [rsi + 0x40]", "mov r9,  [rsi + 0x48]", "mov r10, [rsi + 0x50]", "mov r11, [rsi + 0x58]",
        "mov r12, [rsi + 0x60]", "mov r13, [rsi + 0x68]", "mov r14, [rsi + 0x70]", "mov r15, [rsi + 0x78]",
        
        // Load RSI and RDI last
        "mov rdi, [rsi + 0x28]", 
        "mov rax, [rsi + 0x20]", // Load new RSI into RAX temporarily
        "xchg rax, rsi",         // RSI = new RSI, RAX = old RSI ptr
        
        // Jump to new RIP
        "jmp [rax + 0x80]",      // Jump to new context's RIP
        
        // === RETURN POINT ===
        "2:", // Old context returns here
        "ret",
        options(noreturn)
    );
}

/// Task with full production features
#[derive(Debug)]
pub struct Task {
    pub id: u64,
    pub name: &'static str, 
    pub context: Context,
    pub state: TaskState,
    pub priority: u8,
    pub nice: i8,
    pub time_slice: u64,
    pub runtime_ns: u64,
    pub stack_base: VirtAddr,
    pub stack_size: usize,
    pub memory_usage: usize,
    pub last_scheduled: u64,
    pub cpu_affinity: u32,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaskState {
    Ready,
    Running, 
    Sleeping(u64), // Wake up time
    Blocked,
    Zombie,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityLevel {
    Kernel,      // Full privileges
    System,      // System service
    User,        // User process
    Restricted,  // Sandboxed
}

impl Task {
    /// Create high-performance kernel task
    pub fn new_kernel_task(
        id: u64,
        name: &'static str,
        entry: extern "C" fn(),
        stack_size: usize,
        priority: u8,
    ) -> Result<Self, &'static str> {
        
        let stack_base = allocate_secure_stack(stack_size)?;
        let stack_top = VirtAddr::new(stack_base.as_u64() + stack_size as u64);
        
        let cr3 = unsafe {
            let (frame, _) = x86_64::registers::control::Cr3::read();
            frame.start_address()
        };
        
        let mut context = Context::new_kernel_task(
            VirtAddr::new(entry as *const () as u64),
            stack_top,
            cr3,
        );
        
        // Initialize FPU state for kernel tasks
        context.init_fpu_state()?;
        
        Ok(Task {
            id,
            name,
            context,
            state: TaskState::Ready,
            priority,
            nice: 0,
            time_slice: calculate_time_slice(priority),
            runtime_ns: 0,
            stack_base,
            stack_size,
            memory_usage: stack_size,
            last_scheduled: 0,
            cpu_affinity: 0xFFFFFFFF, // Can run on any CPU
            security_level: SecurityLevel::Kernel,
        })
    }
    
    /// Switch to this task with security validation
    pub unsafe fn switch_to_secure(&mut self, old_ctx: &mut Context) -> Result<(), &'static str> {
        // Security validation
        if !self.validate_security_context() {
            return Err("Security validation failed");
        }
        
        // Update scheduling statistics
        self.last_scheduled = crate::arch::x86_64::time::timer::now_ns();
        self.state = TaskState::Running;
        
        // Log context switch for debugging
        crate::log::logger::log_debug!(
            "Context switch to task '{}' (ID: {})", self.name, self.id
        );
        
        // Perform secure context switch
        switch_context_secure(old_ctx as *mut Context, &self.context as *const Context);
        
        Ok(())
    }
    
    fn validate_security_context(&self) -> bool {
        // Validate task security constraints
        match self.security_level {
            SecurityLevel::Kernel => true, // Kernel tasks can always run
            SecurityLevel::System => {
                // System tasks need valid security token
                self.context.security_token != 0
            },
            SecurityLevel::User => {
                // User tasks need memory limits and capability checks
                self.memory_usage < 64 * 1024 * 1024 && // 64MB limit
                self.context.capability_mask & 0x1000 == 0 // No kernel capabilities
            },
            SecurityLevel::Restricted => {
                // Restricted tasks have very limited capabilities
                self.context.capability_mask == 0 &&
                self.memory_usage < 1024 * 1024 // 1MB limit
            },
        }
    }
}

/// Calculate optimal time slice based on priority
fn calculate_time_slice(priority: u8) -> u64 {
    match priority {
        0..=9 => 50_000_000,   // 50ms for low priority
        10..=19 => 20_000_000, // 20ms for normal priority  
        20..=29 => 10_000_000, // 10ms for high priority
        30..=39 => 5_000_000,  // 5ms for real-time
        _ => 1_000_000,        // 1ms for critical
    }
}

/// Secure stack allocator with guard pages
fn allocate_secure_stack(size: usize) -> Result<VirtAddr, &'static str> {
    let total_size = size + 8192; // Add guard pages (4KB top + 4KB bottom)
    let page_count = (total_size + 4095) / 4096;
    
    // Allocate virtual address range
    let stack_region = crate::memory::virt::allocate_region(
        VirtAddr::new(0xFFFF_FF00_0000_0000), 
        total_size
    )?;
    
    // Map guard page at bottom (no permissions)
    let bottom_guard = stack_region;
    map4k_at(bottom_guard, PhysAddr::new(0), VmFlags::empty())?; // Unreadable, causes page fault
    
    // Map actual stack pages  
    for i in 1..(page_count - 1) {
        let page_addr = VirtAddr::new(stack_region.as_u64() + (i * 4096) as u64);
        if let Some(frame) = alloc(AllocFlags::ZEROED) {
            map4k_at(
                page_addr, 
                PhysAddr::new(frame.0),
                VmFlags::RW | VmFlags::NX // Readable/Writable but not executable
            )?;
        } else {
            return Err("Failed to allocate stack frame");
        }
    }
    
    // Map guard page at top (no permissions)
    let top_guard = VirtAddr::new(stack_region.as_u64() + ((page_count - 1) * 4096) as u64);
    map4k_at(top_guard, PhysAddr::new(0), VmFlags::empty())?;
    
    // Return base of actual stack (after bottom guard)
    Ok(VirtAddr::new(stack_region.as_u64() + 4096))
}

/// Initialize context switching subsystem
pub fn init() -> Result<(), &'static str> {
    crate::log::logger::log_info!("Initializing advanced context switching");
    
    // Verify CPU supports required features
    if !cpu_supports_required_features() {
        return Err("CPU missing required features for context switching");
    }
    
    // Initialize FPU for context switching
    unsafe {
        init_fpu();
    }
    
    crate::log::logger::log_info!("Context switching initialized successfully");
    Ok(())
}

/// Check CPU features required for advanced context switching
fn cpu_supports_required_features() -> bool {
    // Check for FXSAVE/FXRSTOR
    let cpuid = unsafe { core::arch::x86_64::__cpuid(1) };
    let has_fxsr = (cpuid.edx & (1 << 24)) != 0;
    
    // Check for RDGSBASE/WRGSBASE
    let extended_cpuid = unsafe { core::arch::x86_64::__cpuid(0x80000001) };
    let has_gsbase = (extended_cpuid.ecx & (1 << 0)) != 0;
    
    has_fxsr && has_gsbase
}

/// Initialize FPU for context switching
unsafe fn init_fpu() {
    // Enable OSFXSR (OS supports FXSAVE/FXRSTOR)
    let mut cr4 = x86_64::registers::control::Cr4::read();
    cr4 |= x86_64::registers::control::Cr4Flags::OSFXSR;
    cr4 |= x86_64::registers::control::Cr4Flags::OSXMMEXCPT;
    x86_64::registers::control::Cr4::write(cr4);
    
    // Initialize FPU
    asm!("finit");
}

/// Create production test task
pub fn create_performance_test_task() -> Result<Task, &'static str> {
    extern "C" fn perf_test_task() {
        for i in 0..1000000 {
            // Perform some computation
            let _ = i * i + i;
            
            // Yield periodically
            if i % 10000 == 0 {
                crate::sched::schedule_now();
            }
        }
        
        crate::log::logger::log_info!("Performance test task completed");
        
        // Task exit
        loop { unsafe { x86_64::instructions::hlt(); } }
    }
    
    Task::new_kernel_task(
        1001,
        "perf_test",
        perf_test_task,
        16384, // 16KB stack
        15,    // Normal priority
    )
}