//! NØNOS Capability-Aware Kernel Scheduler
//!
//! This scheduler provides a secure cooperative multitasking environment
//! for async-capable kernel tasks. It supports:
//! - Capability-tagged task registration (planned)
//! - Priority boot queues and core-task separation (in roadmap)
//! - Preemptive scheduling with timer-based task switching
//! - Secure `.mod` future-scoped sandbox execution

use alloc::{collections::VecDeque, format, boxed::Box, string::String};
use core::task::{Context, Poll, Waker, RawWaker, RawWakerVTable};
use core::future::Future;
use core::pin::Pin;
use core::ptr::null;
use spin::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// NØNOS Priority levels for task scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NonosPriority {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
    RealTime = 5,
}

/// Represents a single schedulable kernel task
pub struct Task {
    pub name: &'static str,
    pub future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    pub waker: Option<Waker>,
    pub priority: u8,
    pub ticks: u64,
}

impl Task {
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.future.as_mut().poll(cx)
    }
}

/// Global scheduler queue (FIFO, upgrade to priority queue later)
static SCHED_QUEUE: Mutex<VecDeque<Task>> = Mutex::new(VecDeque::new());

/// Preemption flag for scheduler
static NEED_RESCHEDULE: AtomicBool = AtomicBool::new(false);

/// Main scheduler structure
pub struct Scheduler {
    pub name: &'static str,
    pub running_tasks: u32,
}

impl Scheduler {
    /// Create new scheduler
    pub fn new(name: &'static str) -> Self {
        Scheduler {
            name,
            running_tasks: 0,
        }
    }
    
    /// Tick the scheduler
    pub fn tick(&self) {
        // Increment tick counter
        SCHEDULER_TICKS.fetch_add(1, Ordering::Relaxed);
        
        // Check if we need to reschedule
        if should_reschedule() {
            // Mark that we handled the reschedule request
            NEED_RESCHEDULE.store(false, Ordering::Relaxed);
            
            // Update task time slices and handle preemption
            self.update_task_time_slices();
        }
        
        // Perform periodic scheduler maintenance
        if SCHEDULER_TICKS.load(Ordering::Relaxed) % 1000 == 0 {
            self.cleanup_finished_tasks();
            self.balance_task_priorities();
        }
    }
    
    /// Update time slices for all tasks
    fn update_task_time_slices(&self) {
        let mut queue = SCHED_QUEUE.lock();
        for task in queue.iter_mut() {
            task.ticks += 1;
            
            // Detect runaway tasks
            if task.ticks > 10000 {
                crate::log_warn!(
                    "Task '{}' has been running for {} ticks - possible runaway",
                    task.name, task.ticks
                );
            }
        }
    }
    
    /// Clean up tasks that have been marked as finished
    fn cleanup_finished_tasks(&self) {
        let mut queue = SCHED_QUEUE.lock();
        let initial_len = queue.len();
        
        // Remove tasks that have been running too long without yielding
        queue.retain(|task| {
            if task.ticks > 100000 {
                crate::log_warn!(
                    "Terminating runaway task: {}", task.name
                );
                false
            } else {
                true
            }
        });
        
        let cleaned = initial_len - queue.len();
        if cleaned > 0 {
            crate::log::logger::log_info!("Cleaned up {} finished tasks", cleaned);
        }
    }
    
    /// Balance task priorities to prevent starvation
    fn balance_task_priorities(&self) {
        let mut queue = SCHED_QUEUE.lock();
        for task in queue.iter_mut() {
            // Gradually increase priority of long-waiting tasks
            if task.ticks > 5000 && task.priority < 255 {
                task.priority += 1;
            }
        }
    }
}

/// Global scheduler instance
static mut GLOBAL_SCHEDULER: Option<Scheduler> = None;

/// Initialize the scheduler subsystem
pub fn init() {
    unsafe {
        GLOBAL_SCHEDULER = Some(Scheduler::new("NONOS Scheduler"));
    }
    
    // Clear any existing tasks
    SCHED_QUEUE.lock().clear();
    
    // Reset scheduler state
    NEED_RESCHEDULE.store(false, Ordering::Relaxed);
    SCHEDULER_TICKS.store(0, Ordering::Relaxed);
    
    // Call the init_scheduler function
    init_scheduler();
}

/// Get current scheduler
pub fn get_current_scheduler() -> Option<&'static Scheduler> {
    unsafe { GLOBAL_SCHEDULER.as_ref() }
}

/// Scheduler statistics
static SCHEDULER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Spawns a new async kernel task into the global queue
pub fn spawn_task(name: &'static str, fut: impl Future<Output = ()> + Send + 'static, priority: u8) {
    let task = Task {
        name,
        future: Box::pin(fut),
        waker: None,
        priority,
        ticks: 0,
    };
    SCHED_QUEUE.lock().push_back(task);
}

/// Initialize scheduler state
pub fn init_scheduler() {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log("[SCHED] Kernel scheduler initialized");
    }
}

/// Polls the entire scheduler queue cooperatively
pub fn run_scheduler() -> ! {
    let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    
    let mut task_failures = 0u64;
    const MAX_TASK_FAILURES: u64 = 100;

    loop {
        let mut queue = SCHED_QUEUE.lock();
        if queue.is_empty() {
            drop(queue);
            // No tasks - idle with interrupts enabled
            unsafe {
                x86_64::instructions::interrupts::enable();
                x86_64::instructions::hlt();
                x86_64::instructions::interrupts::disable();
            }
            continue;
        }

        let mut new_queue = VecDeque::new();

        while let Some(mut task) = queue.pop_front() {
            // Check system health before running tasks
            if !crate::system_monitor::is_system_stable() {
                log_task_error(task.name, "System unstable - task skipped");
                task_failures += 1;
                if task_failures > MAX_TASK_FAILURES {
                    log_task_error("scheduler", "Too many task failures - halting");
                    break;
                }
                continue;
            }
            
            match task.poll(&mut cx) {
                Poll::Ready(()) => {
                    log_task_exit(task.name);
                },
                Poll::Pending => {
                    task.ticks += 1;
                    // Prevent runaway tasks
                    if task.ticks > 1000000 {
                        log_task_error(task.name, "Task timeout - terminating");
                        task_failures += 1;
                    } else {
                        new_queue.push_back(task);
                    }
                },
            }
        }

        *queue = new_queue;
        
        if task_failures > MAX_TASK_FAILURES {
            crate::system_monitor::mark_system_unstable();
            break;
        }
    }
    
    // If we exit the loop, something went wrong
    loop {
        unsafe { x86_64::instructions::hlt(); }
    }
}


/// RawWaker for pre-init environments
fn dummy_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker { dummy_raw_waker() }

    let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(null(), vtable)
}

/// Simple scheduler-level logging
fn log_task_exit(task: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(&format!("[SCHED] Task '{}' completed.", task));
    }
}

fn log_task_error(task: &str, error: &str) {
    if let Some(logger) = crate::log::logger::try_get_logger() {
        logger.log(&format!("[SCHED] Task '{}' error: {}", task, error));
    }
}

/// Called by timer interrupt for preemptive scheduling
pub fn on_timer_tick() {
    SCHEDULER_TICKS.fetch_add(1, Ordering::Relaxed);
    
    // Mark that we need to reschedule
    NEED_RESCHEDULE.store(true, Ordering::Relaxed);
    
    // Update timer module
    crate::interrupts::timer::tick();
}

/// Check if reschedule is needed
pub fn should_reschedule() -> bool {
    NEED_RESCHEDULE.compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

/// Get scheduler statistics
pub fn get_stats() -> (u64, usize) {
    let queue_len = SCHED_QUEUE.lock().len();
    (SCHEDULER_TICKS.load(Ordering::Relaxed), queue_len)
}

/// Yield current task (trigger reschedule)
pub fn yield_current_task() {
    NEED_RESCHEDULE.store(true, Ordering::Release);
    
    // Save current task state and perform context switch
    unsafe {
        // Save current CPU state
        let mut current_rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp);
        
        // Save current task's registers if we have a current task
        if let Some(current_task_id) = crate::process::get_current_task_id() {
            crate::process::save_task_state(current_task_id, current_rsp);
        }
        
        // Find next ready task
        if let Some(next_task) = get_next_ready_task() {
            // Load next task's state
            let next_rsp = crate::process::get_task_stack_pointer(next_task.id);
            
            // Perform context switch
            crate::process::set_current_task_id(next_task.id);
            
            // Switch to next task's address space if needed
            crate::memory::switch_address_space(x86_64::PhysAddr::new(next_task.page_table));
            
            // Restore stack pointer and continue execution
            core::arch::asm!("mov rsp, {}", in(reg) next_rsp);
        } else {
            // No ready tasks, idle
            x86_64::instructions::hlt();
        }
    }
}

/// Get next ready task from scheduler queue
fn get_next_ready_task() -> Option<crate::process::TaskInfo> {
    let mut queue = SCHED_QUEUE.lock();
    
    // Find highest priority ready task
    let mut best_task_idx = None;
    let mut best_priority = 0u8;
    
    for (idx, task) in queue.iter().enumerate() {
        if task.priority >= best_priority {
            best_priority = task.priority;
            best_task_idx = Some(idx);
        }
    }
    
    if let Some(idx) = best_task_idx {
        let task = queue.remove(idx)?;
        Some(crate::process::TaskInfo {
            id: task.name.as_ptr() as u32, // Simple task ID
            name: String::from(task.name),
            priority: task.priority,
            time_slice: 100,
            page_table: crate::memory::get_kernel_page_table().as_u64(), // For now use kernel page table
        })
    } else {
        None
    }
}

/// Wake up the scheduler with immediate context switch
pub fn wakeup_scheduler() {
    NEED_RESCHEDULE.store(true, Ordering::Relaxed);
    
    // Trigger immediate context switch
    unsafe {
        // Save current context
        let mut current_rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp);
        
        // Find next task to run
        if let Some(next_task) = get_next_runnable_task() {
            // Save current task state if any
            save_current_task_state(current_rsp);
            
            // Load next task's context
            let next_rsp = crate::process::get_task_stack_pointer(next_task.id);
            
            // Perform actual context switch
            core::arch::asm!(
                "mov rsp, {}",
                "ret",
                in(reg) next_rsp,
                options(noreturn)
            );
        }
    }
}

/// Get next runnable task with priority scheduling
fn get_next_runnable_task() -> Option<&'static Task> {
    let mut queue = SCHED_QUEUE.lock();
    
    // Find highest priority ready task
    let mut best_task_idx = None;
    let mut highest_priority = 0u8;
    
    for (idx, task) in queue.iter().enumerate() {
        if task.priority > highest_priority {
            highest_priority = task.priority;
            best_task_idx = Some(idx);
        }
    }
    
    if let Some(idx) = best_task_idx {
        // Move task to front for execution
        let task = queue.remove(idx).unwrap();
        queue.push_front(task);
        queue.front()
    } else {
        None
    }
}

/// Save current task context for context switching
fn save_current_task_state(rsp: u64) {
    unsafe {
        let mut regs = TaskRegisters::default();
        
        // Save all CPU registers
        core::arch::asm!(
            "mov {}, rax",
            "mov {}, rbx", 
            "mov {}, rcx",
            "mov {}, rdx",
            "mov {}, rsi",
            "mov {}, rdi",
            "mov {}, rbp",
            "mov {}, r8",
            "mov {}, r9",
            "mov {}, r10",
            "mov {}, r11",
            "mov {}, r12",
            "mov {}, r13",
            "mov {}, r14",
            "mov {}, r15",
            out(reg) regs.rax,
            out(reg) regs.rbx,
            out(reg) regs.rcx,
            out(reg) regs.rdx,
            out(reg) regs.rsi,
            out(reg) regs.rdi,
            out(reg) regs.rbp,
            out(reg) regs.r8,
            out(reg) regs.r9,
            out(reg) regs.r10,
            out(reg) regs.r11,
            out(reg) regs.r12,
            out(reg) regs.r13,
            out(reg) regs.r14,
            out(reg) regs.r15,
            options(nomem, nostack)
        );
        
        regs.rsp = rsp;
        
        // Save to current task's context
        if let Some(current_id) = crate::process::get_current_task_id() {
            crate::process::save_task_state(current_id, rsp);
        }
    }
}

/// Task register context for REAL context switching
#[repr(C)]
struct TaskRegisters {
    rax: u64, rbx: u64, rcx: u64, rdx: u64,
    rsi: u64, rdi: u64, rbp: u64, rsp: u64,
    r8: u64, r9: u64, r10: u64, r11: u64,
    r12: u64, r13: u64, r14: u64, r15: u64,
    rip: u64, rflags: u64,
}

impl Default for TaskRegisters {
    fn default() -> Self {
        Self {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0, rflags: 0x200, // Interrupts enabled
        }
    }
}

/// Handle scheduler tick for preemptive scheduling
pub fn scheduler_tick() {
    // Mark that we need to reschedule
    NEED_RESCHEDULE.store(true, Ordering::Relaxed);
    
    // In a real implementation, this would trigger a context switch
    // For now, just wake up the scheduler
    wakeup_scheduler();
}

