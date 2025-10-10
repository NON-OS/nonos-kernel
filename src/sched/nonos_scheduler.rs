#![no_std]

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use x86_64::VirtAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosProcessState {
    Created = 0,
    Ready = 1,
    Running = 2,
    Blocked = 3,
    Terminated = 4,
    Zombie = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosPriority {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
    RealTime = 5,
}

#[derive(Debug)]
pub struct NonosProcessControlBlock {
    pub process_id: u64,
    pub parent_id: Option<u64>,
    pub state: NonosProcessState,
    pub priority: NonosPriority,
    pub quantum_remaining: u64,
    pub total_time: u64,
    pub memory_base: Option<VirtAddr>,
    pub memory_size: usize,
    pub stack_pointer: u64,
    pub instruction_pointer: u64,
    pub capabilities: Vec<u64>,
    pub isolation_domain: u64,
    pub security_level: u8,
    pub created_time: u64,
    pub last_scheduled: u64,
}

#[derive(Debug)]
pub struct NonosProductionScheduler {
    processes: RwLock<BTreeMap<u64, NonosProcessControlBlock>>,
    ready_queues: [Mutex<Vec<u64>>; 6], // One for each priority level
    running_process: RwLock<Option<u64>>,
    next_process_id: AtomicU64,
    quantum_size_ns: u64,
    current_quantum: AtomicU64,
    total_processes: AtomicUsize,
    context_switches: AtomicU64,
    scheduler_enabled: AtomicBool,
}

impl NonosProductionScheduler {
    pub const fn new() -> Self {
        Self {
            processes: RwLock::new(BTreeMap::new()),
            ready_queues: [
                Mutex::new(Vec::new()), // Idle
                Mutex::new(Vec::new()), // Low
                Mutex::new(Vec::new()), // Normal
                Mutex::new(Vec::new()), // High
                Mutex::new(Vec::new()), // Critical
                Mutex::new(Vec::new()), // RealTime
            ],
            running_process: RwLock::new(None),
            next_process_id: AtomicU64::new(1),
            quantum_size_ns: 10_000_000, // 10ms default quantum
            current_quantum: AtomicU64::new(0),
            total_processes: AtomicUsize::new(0),
            context_switches: AtomicU64::new(0),
            scheduler_enabled: AtomicBool::new(false),
        }
    }

    pub fn create_process(
        &self,
        parent_id: Option<u64>,
        priority: NonosPriority,
        memory_size: usize,
        entry_point: u64,
    ) -> Result<u64, &'static str> {
        let process_id = self.next_process_id.fetch_add(1, Ordering::SeqCst);
        let current_time = self.get_timestamp();

        let pcb = NonosProcessControlBlock {
            process_id,
            parent_id,
            state: NonosProcessState::Created,
            priority,
            quantum_remaining: self.quantum_size_ns,
            total_time: 0,
            memory_base: None, // Need to be allocated
            memory_size,
            stack_pointer: 0, // Need to be set up properly
            instruction_pointer: entry_point,
            capabilities: Vec::new(),
            isolation_domain: self.assign_isolation_domain(process_id),
            security_level: self.calculate_security_level(priority),
            created_time: current_time,
            last_scheduled: 0,
        };

        // Add to process table
        self.processes.write().insert(process_id, pcb);

        // Add to appropriate ready queue
        self.add_to_ready_queue(process_id, priority);

        self.total_processes.fetch_add(1, Ordering::SeqCst);

        Ok(process_id)
    }

    pub fn schedule(&self) -> Option<u64> {
        if !self.scheduler_enabled.load(Ordering::SeqCst) {
            return None;
        }

        // Check if current process quantum expired
        if let Some(current_pid) = *self.running_process.read() {
            let current_quantum = self.current_quantum.load(Ordering::SeqCst);
            if current_quantum >= self.quantum_size_ns {
                // Preempt current process
                self.preempt_process(current_pid);
            } else {
                // Continue running current process
                return Some(current_pid);
            }
        }

        // Find next process to run (highest priority first)
        for priority_level in (0..6).rev() {
            let mut queue = self.ready_queues[priority_level].lock();
            if let Some(process_id) = queue.pop() {
                // Update process state
                if let Some(pcb) = self.processes.write().get_mut(&process_id) {
                    pcb.state = NonosProcessState::Running;
                    pcb.last_scheduled = self.get_timestamp();
                    pcb.quantum_remaining = self.quantum_size_ns;
                }

                // Set as running process
                *self.running_process.write() = Some(process_id);
                self.current_quantum.store(0, Ordering::SeqCst);
                self.context_switches.fetch_add(1, Ordering::SeqCst);

                return Some(process_id);
            }
        }

        // No processes ready to run
        None
    }

    pub fn terminate_process(&self, process_id: u64) -> Result<(), &'static str> {
        let mut processes = self.processes.write();
        let pcb = processes.get_mut(&process_id).ok_or("Process not found")?;

        // Update state
        pcb.state = NonosProcessState::Terminated;

        // Remove from running if it's currently running
        let mut running = self.running_process.write();
        if *running == Some(process_id) {
            *running = None;
        }

        // Remove from ready queues
        for queue in &self.ready_queues {
            let mut q = queue.lock();
            q.retain(|&pid| pid != process_id);
        }

        self.total_processes.fetch_sub(1, Ordering::SeqCst);

        Ok(())
    }

    pub fn block_process(&self, process_id: u64, reason: &str) -> Result<(), &'static str> {
        let mut processes = self.processes.write();
        let pcb = processes.get_mut(&process_id).ok_or("Process not found")?;

        pcb.state = NonosProcessState::Blocked;

        // Remove from ready queues
        for queue in &self.ready_queues {
            let mut q = queue.lock();
            q.retain(|&pid| pid != process_id);
        }

        let mut running = self.running_process.write();
        if *running == Some(process_id) {
            *running = None;
        }

        Ok(())
    }

    pub fn unblock_process(&self, process_id: u64) -> Result<(), &'static str> {
        let mut processes = self.processes.write();
        let pcb = processes.get_mut(&process_id).ok_or("Process not found")?;

        if pcb.state != NonosProcessState::Blocked {
            return Err("Process not blocked");
        }

        pcb.state = NonosProcessState::Ready;
        self.add_to_ready_queue(process_id, pcb.priority);

        Ok(())
    }

    pub fn set_process_priority(
        &self,
        process_id: u64,
        priority: NonosPriority,
    ) -> Result<(), &'static str> {
        let mut processes = self.processes.write();
        let pcb = processes.get_mut(&process_id).ok_or("Process not found")?;

        let old_priority = pcb.priority;
        pcb.priority = priority;

        // If process is ready, move between queues
        if pcb.state == NonosProcessState::Ready {
            // Remove from old queue
            let mut old_queue = self.ready_queues[old_priority as usize].lock();
            old_queue.retain(|&pid| pid != process_id);
            drop(old_queue);

            // Add to new queue
            self.add_to_ready_queue(process_id, priority);
        }

        Ok(())
    }

    pub fn get_process_info(&self, process_id: u64) -> Result<NonosProcessInfo, &'static str> {
        let processes = self.processes.read();
        let pcb = processes.get(&process_id).ok_or("Process not found")?;

        Ok(NonosProcessInfo {
            process_id: pcb.process_id,
            parent_id: pcb.parent_id,
            state: pcb.state,
            priority: pcb.priority,
            total_time: pcb.total_time,
            memory_size: pcb.memory_size,
            isolation_domain: pcb.isolation_domain,
            security_level: pcb.security_level,
            created_time: pcb.created_time,
            last_scheduled: pcb.last_scheduled,
        })
    }

    pub fn enable_scheduler(&self) {
        self.scheduler_enabled.store(true, Ordering::SeqCst);
    }

    pub fn disable_scheduler(&self) {
        self.scheduler_enabled.store(false, Ordering::SeqCst);
    }

    pub fn tick(&self) {
        // Called by timer interrupt to update quantum
        self.current_quantum.fetch_add(1_000_000, Ordering::SeqCst); // Add 1ms

        // Update total time for running process
        if let Some(current_pid) = *self.running_process.read() {
            if let Some(pcb) = self.processes.write().get_mut(&current_pid) {
                pcb.total_time += 1_000_000; // Add 1ms
            }
        }
    }

    fn preempt_process(&self, process_id: u64) {
        if let Some(pcb) = self.processes.write().get_mut(&process_id) {
            pcb.state = NonosProcessState::Ready;
            self.add_to_ready_queue(process_id, pcb.priority);
        }

        *self.running_process.write() = None;
    }

    fn add_to_ready_queue(&self, process_id: u64, priority: NonosPriority) {
        self.ready_queues[priority as usize].lock().push(process_id);
    }

    fn assign_isolation_domain(&self, process_id: u64) -> u64 {
        // Simple domain assignment - in production this would be more sophisticated
        process_id % 16
    }

    fn calculate_security_level(&self, priority: NonosPriority) -> u8 {
        match priority {
            NonosPriority::RealTime => 5,
            NonosPriority::Critical => 4,
            NonosPriority::High => 3,
            NonosPriority::Normal => 2,
            NonosPriority::Low => 1,
            NonosPriority::Idle => 0,
        }
    }

    fn get_timestamp(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    pub fn get_scheduler_stats(&self) -> NonosSchedulerStats {
        NonosSchedulerStats {
            total_processes: self.total_processes.load(Ordering::SeqCst),
            context_switches: self.context_switches.load(Ordering::SeqCst),
            current_quantum: self.current_quantum.load(Ordering::SeqCst),
            scheduler_enabled: self.scheduler_enabled.load(Ordering::SeqCst),
            running_process: *self.running_process.read(),
        }
    }
}

#[derive(Debug)]
pub struct NonosProcessInfo {
    pub process_id: u64,
    pub parent_id: Option<u64>,
    pub state: NonosProcessState,
    pub priority: NonosPriority,
    pub total_time: u64,
    pub memory_size: usize,
    pub isolation_domain: u64,
    pub security_level: u8,
    pub created_time: u64,
    pub last_scheduled: u64,
}

#[derive(Debug)]
pub struct NonosSchedulerStats {
    pub total_processes: usize,
    pub context_switches: u64,
    pub current_quantum: u64,
    pub scheduler_enabled: bool,
    pub running_process: Option<u64>,
}

// Global scheduler instance
pub static NONOS_PRODUCTION_SCHEDULER: NonosProductionScheduler = NonosProductionScheduler::new();

// Convenience functions
pub fn create_process(
    parent_id: Option<u64>,
    priority: NonosPriority,
    memory_size: usize,
    entry_point: u64,
) -> Result<u64, &'static str> {
    NONOS_PRODUCTION_SCHEDULER.create_process(parent_id, priority, memory_size, entry_point)
}

pub fn schedule_next_process() -> Option<u64> {
    NONOS_PRODUCTION_SCHEDULER.schedule()
}

pub fn terminate_process(process_id: u64) -> Result<(), &'static str> {
    NONOS_PRODUCTION_SCHEDULER.terminate_process(process_id)
}

pub fn enable_scheduler() {
    NONOS_PRODUCTION_SCHEDULER.enable_scheduler();
}

pub fn disable_scheduler() {
    NONOS_PRODUCTION_SCHEDULER.disable_scheduler();
}

pub fn scheduler_tick() {
    NONOS_PRODUCTION_SCHEDULER.tick();
}
