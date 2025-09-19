//! Advanced Task Management System
//! 
//! Provides capability-aware task spawning with priority and affinity control

use core::future::Future;

/// Task identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub u64);

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Idle = 0,
    Low = 1,
    Normal = 2, 
    High = 3,
    Realtime = 4,
    Critical = 5,
}

/// CPU affinity specification
#[derive(Debug, Clone, Copy)]
pub enum Affinity {
    ANY,
    Core(u32),
    Package(u32),
}

/// Spawn a new kernel task with advanced scheduling parameters
pub fn kspawn(
    name: &'static str,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    priority: Priority,
    affinity: Affinity,
) {
    // Convert C function to async future
    let future = KernelTaskFuture::new(name, entry, arg);
    let priority_num = match priority {
        Priority::Idle => 0,
        Priority::Low => 1,
        Priority::Normal => 2,
        Priority::High => 3,
        Priority::Realtime => 4,
        Priority::Critical => 5,
    };
    
    crate::sched::scheduler::spawn_task(name, future, priority_num);
}

/// Wrapper to convert kernel thread to async future
struct KernelTaskFuture {
    name: &'static str,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
    started: bool,
}

impl KernelTaskFuture {
    fn new(name: &'static str, entry: extern "C" fn(usize) -> !, arg: usize) -> Self {
        Self {
            name,
            entry,
            arg,
            started: false,
        }
    }
}

impl Future for KernelTaskFuture {
    type Output = ();
    
    fn poll(mut self: core::pin::Pin<&mut Self>, _cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        if !self.started {
            self.started = true;
            
            // Allocate new stack for user task
            let stack_size = 64 * 1024; // 64KB stack
            let stack_addr = crate::memory::alloc_kernel_stack()
                .expect("Failed to allocate task stack");
            
            // Set up initial stack frame for task
            unsafe {
                let stack_top = stack_addr + stack_size as usize;
                
                // Create initial stack frame with entry point
                let stack_ptr = stack_top - 8u64;
                *(stack_ptr.as_u64() as *mut u64) = self.entry as *const () as u64; // Return address
                
                // Save task context
                let _task_context = crate::process::create_task_context(
                    stack_ptr.as_u64(),
                    self.entry as *const () as u64
                );
                
                // Execute entry point in new context
                let result = self.execute_task_entry();
                
                // Clean up stack when task completes
                crate::memory::free_kernel_stack(stack_addr);
                
                return core::task::Poll::Ready(result);
            }
        }
        core::task::Poll::Pending
    }
}

impl KernelTaskFuture {
    /// Execute task entry point in isolated context
    unsafe fn execute_task_entry(&self) -> () {
        // Generate task ID from name pointer
        let task_id = self.name.as_ptr() as u32;
        
        // Set up task execution context
        crate::arch::x86_64::set_task_context(task_id);
        
        // Create function pointer from entry point  
        let task_fn: extern "C" fn(usize) -> ! = self.entry;
        
        // Call the task function with argument - this never returns
        task_fn(self.arg);
        
        // Unreachable code
        unreachable!("Task function should never return");
    }
}

/// Get current task ID
pub fn current() -> TaskId {
    // Simple implementation - return a fixed ID for now
    TaskId(1)
}
