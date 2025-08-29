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
//! NONOS first Process Scheduler
//!
//! Multi-class scheduler with real-time, fair scheduling, and NUMA awareness

use alloc::{vec::Vec, collections::{BTreeMap, VecDeque}, format};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use spin::Mutex;
use crate::process::{
    process::{Process, ProcessId, ProcessState, Priority},
    numa::{NumaNodeId, get_topology},
};

/// Scheduler classes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchedulerClass {
    RealTime,    // RT scheduler (SCHED_FIFO, SCHED_RR)
    Fair,        // CFS (Completely Fair Scheduler)
    Idle,        // Idle class scheduler  
    Deadline,    // Deadline scheduler (SCHED_DEADLINE)
}

/// Scheduling policy
#[derive(Debug, Clone, Copy)]
pub enum SchedulingPolicy {
    Normal,      // SCHED_NORMAL (CFS)
    Fifo,        // SCHED_FIFO (RT)
    RoundRobin,  // SCHED_RR (RT)
    Batch,       // SCHED_BATCH 
    Idle,        // SCHED_IDLE
    Deadline,    // SCHED_DEADLINE
}

/// Deadline scheduling parameters
#[derive(Debug, Clone, Copy)]
pub struct DeadlineParams {
    pub runtime: u64,    // Execution time per period
    pub deadline: u64,   // Deadline relative to period start
    pub period: u64,     // Period length
}

/// Scheduling entity (represents a schedulable unit)
#[derive(Debug)]
pub struct SchedEntity {
    pub process_id: ProcessId,
    pub vruntime: u64,           // Virtual runtime for CFS
    pub load_weight: u32,        // Load weight for CFS
    pub time_slice: u32,         // Time slice remaining
    pub last_ran: u64,           // Last execution time
    pub exec_start: u64,         // Execution start time
    pub sum_exec_runtime: u64,   // Total execution time
    pub deadline_params: Option<DeadlineParams>,
    pub numa_node: Option<NumaNodeId>,
    pub cpu_affinity: u64,       // CPU affinity mask
}

/// Per-CPU run queue
#[derive(Debug)]
pub struct CpuRunQueue {
    pub cpu_id: u32,
    pub numa_node: Option<NumaNodeId>,
    
    // Real-time run queues (priority 0-99)
    pub rt_queues: Vec<VecDeque<ProcessId>>,
    pub rt_queue_bitmap: u128,  // Bitmap of non-empty RT queues
    
    // CFS (Completely Fair Scheduler) red-black tree
    pub cfs_entities: BTreeMap<u64, ProcessId>, // vruntime -> process
    pub cfs_min_vruntime: u64,
    pub cfs_nr_running: u32,
    pub cfs_load_weight: u64,
    
    // Deadline scheduler
    pub deadline_entities: Vec<ProcessId>,
    
    // Idle tasks
    pub idle_queue: VecDeque<ProcessId>,
    
    // Current running task
    pub current_task: Option<ProcessId>,
    
    // Load balancing
    pub load_avg: u64,
    pub cpu_capacity: u32,
    
    // Statistics
    pub context_switches: AtomicU64,
    pub idle_time: AtomicU64,
    pub system_time: AtomicU64,
    pub user_time: AtomicU64,
}

impl CpuRunQueue {
    /// Create new CPU run queue
    pub fn new(cpu_id: u32, numa_node: Option<NumaNodeId>) -> Self {
        let mut rt_queues = Vec::with_capacity(100);
        for _ in 0..100 {
            rt_queues.push(VecDeque::new());
        }
        
        CpuRunQueue {
            cpu_id,
            numa_node,
            rt_queues,
            rt_queue_bitmap: 0,
            cfs_entities: BTreeMap::new(),
            cfs_min_vruntime: 0,
            cfs_nr_running: 0,
            cfs_load_weight: 0,
            deadline_entities: Vec::new(),
            idle_queue: VecDeque::new(),
            current_task: None,
            load_avg: 0,
            cpu_capacity: 1000, // Default capacity
            context_switches: AtomicU64::new(0),
            idle_time: AtomicU64::new(0),
            system_time: AtomicU64::new(0),
            user_time: AtomicU64::new(0),
        }
    }
    
    /// Enqueue process based on scheduling class
    pub fn enqueue(&mut self, process: &Process, entity: &SchedEntity) {
        match entity.deadline_params {
            Some(_) => {
                // Deadline scheduler
                self.deadline_entities.push(process.pid);
            },
            None => {
                match process.priority {
                    Priority::RealTime(rt_prio) => {
                        // Real-time scheduler
                        let prio = rt_prio as usize;
                        self.rt_queues[prio].push_back(process.pid);
                        self.rt_queue_bitmap |= 1u128 << prio;
                    },
                    Priority::Normal(_) => {
                        // CFS scheduler
                        self.cfs_entities.insert(entity.vruntime, process.pid);
                        self.cfs_nr_running += 1;
                        self.cfs_load_weight += entity.load_weight as u64;
                    },
                    Priority::Idle => {
                        // Idle scheduler
                        self.idle_queue.push_back(process.pid);
                    }
                }
            }
        }
    }
    
    /// Pick next task to run
    pub fn pick_next(&mut self) -> Option<ProcessId> {
        // 1. Check deadline tasks first (highest priority)
        if !self.deadline_entities.is_empty() {
            // Sort by deadline and pick earliest
            // Simplified: just pick first
            return self.deadline_entities.pop();
        }
        
        // 2. Check real-time tasks
        if self.rt_queue_bitmap != 0 {
            let highest_prio = self.rt_queue_bitmap.leading_zeros() as usize;
            if let Some(queue) = self.rt_queues.get_mut(highest_prio) {
                if let Some(pid) = queue.pop_front() {
                    if queue.is_empty() {
                        self.rt_queue_bitmap &= !(1u128 << highest_prio);
                    }
                    return Some(pid);
                }
            }
        }
        
        // 3. Check CFS tasks
        if let Some((&vruntime, &pid)) = self.cfs_entities.iter().next() {
            self.cfs_entities.remove(&vruntime);
            self.cfs_nr_running -= 1;
            return Some(pid);
        }
        
        // 4. Check idle tasks
        self.idle_queue.pop_front()
    }
    
    /// Update CFS virtual runtime
    pub fn update_cfs_vruntime(&mut self, entity: &mut SchedEntity, delta: u64) {
        let old_vruntime = entity.vruntime;
        
        // Calculate new vruntime based on load weight
        let weighted_delta = delta * 1024 / entity.load_weight as u64;
        entity.vruntime += weighted_delta;
        
        // Update minimum vruntime
        if entity.vruntime < self.cfs_min_vruntime {
            self.cfs_min_vruntime = entity.vruntime;
        }
        
        // Re-insert into tree if still running
        if old_vruntime != entity.vruntime {
            self.cfs_entities.remove(&old_vruntime);
            self.cfs_entities.insert(entity.vruntime, entity.process_id);
        }
    }
    
    /// Calculate load average
    pub fn update_load_avg(&mut self) {
        let running_tasks = self.cfs_nr_running + 
                           self.rt_queues.iter().map(|q| q.len() as u32).sum::<u32>() +
                           self.deadline_entities.len() as u32;
        
        // Simple exponential moving average
        self.load_avg = (self.load_avg * 9 + running_tasks as u64 * 100) / 10;
    }
}

/// Global process scheduler
pub struct ProcessScheduler {
    /// Per-CPU run queues
    cpu_queues: Vec<CpuRunQueue>,
    
    /// Process table
    processes: BTreeMap<ProcessId, Process>,
    
    /// Scheduling entities
    entities: BTreeMap<ProcessId, SchedEntity>,
    
    /// Scheduler statistics
    total_context_switches: AtomicU64,
    load_balance_count: AtomicU64,
    migration_count: AtomicU64,
    
    /// Configuration
    nr_cpus: u32,
    sched_latency: u64,     // Target latency for CFS
    min_granularity: u64,   // Minimum time slice
    
    /// Load balancing
    load_balance_interval: u64,
    last_load_balance: AtomicU64,
}

impl ProcessScheduler {
    /// Create new scheduler
    pub fn new(nr_cpus: u32) -> Self {
        let mut cpu_queues = Vec::with_capacity(nr_cpus as usize);
        
        for cpu_id in 0..nr_cpus {
            // Detect NUMA node for CPU
            let numa_node = if let Some(topology) = get_topology() {
                topology.node_for_cpu(cpu_id)
            } else {
                None
            };
            
            cpu_queues.push(CpuRunQueue::new(cpu_id, numa_node));
        }
        
        ProcessScheduler {
            cpu_queues,
            processes: BTreeMap::new(),
            entities: BTreeMap::new(),
            total_context_switches: AtomicU64::new(0),
            load_balance_count: AtomicU64::new(0),
            migration_count: AtomicU64::new(0),
            nr_cpus,
            sched_latency: 6_000_000, // 6ms in nanoseconds
            min_granularity: 750_000,  // 0.75ms
            load_balance_interval: 1_000_000, // 1ms
            last_load_balance: AtomicU64::new(0),
        }
    }
    
    /// Add new process
    pub fn add_process(&mut self, process: Process) -> Result<(), &'static str> {
        let pid = process.pid;
        
        // Create scheduling entity
        let entity = SchedEntity {
            process_id: pid,
            vruntime: 0,
            load_weight: self.calculate_load_weight(&process),
            time_slice: self.calculate_time_slice(&process),
            last_ran: 0,
            exec_start: 0,
            sum_exec_runtime: 0,
            deadline_params: None, // Set later if needed
            numa_node: process.numa_node.as_ref().map(|n| n.node_id),
            cpu_affinity: process.cpu_affinity,
        };
        
        // Select initial CPU
        let cpu_id = self.select_cpu_for_process(&process, &entity)?;
        
        // Add to appropriate run queue
        if let Some(cpu_queue) = self.cpu_queues.get_mut(cpu_id as usize) {
            cpu_queue.enqueue(&process, &entity);
        }
        
        self.entities.insert(pid, entity);
        self.processes.insert(pid, process);
        
        Ok(())
    }
    
    /// Remove process
    pub fn remove_process(&mut self, pid: ProcessId) -> Option<Process> {
        self.entities.remove(&pid);
        self.processes.remove(&pid)
    }
    
    /// Schedule next task for CPU
    pub fn schedule(&mut self, cpu_id: u32) -> Option<ProcessId> {
        if let Some(cpu_queue) = self.cpu_queues.get_mut(cpu_id as usize) {
            let next_pid = cpu_queue.pick_next()?;
            
            // Update current task
            cpu_queue.current_task = Some(next_pid);
            
            // Update statistics
            cpu_queue.context_switches.fetch_add(1, Ordering::Relaxed);
            self.total_context_switches.fetch_add(1, Ordering::Relaxed);
            
            Some(next_pid)
        } else {
            None
        }
    }
    
    /// Calculate load weight for process
    fn calculate_load_weight(&self, process: &Process) -> u32 {
        match process.priority {
            Priority::RealTime(_) => 1000, // RT tasks have fixed high weight
            Priority::Normal(nice) => {
                // Convert nice value (-20 to 19) to weight
                let nice_clamped = nice.max(-20).min(19);
                let weight_table = [
                    88761, 71755, 56483, 46273, 36291, // nice -20 to -16
                    29154, 23254, 18705, 14949, 11916, // nice -15 to -11  
                    9548, 7620, 6100, 4904, 3906,      // nice -10 to -6
                    3121, 2501, 1991, 1586, 1277,      // nice -5 to -1
                    1024,                               // nice 0
                    820, 655, 526, 423, 335,           // nice 1 to 5
                    272, 215, 172, 137, 110,           // nice 6 to 10
                    87, 70, 56, 45, 36,                // nice 11 to 15
                    29, 23, 18, 15, 12,                // nice 16 to 19
                ];
                weight_table[(nice_clamped + 20) as usize]
            },
            Priority::Idle => 100, // Very low weight
        }
    }
    
    /// Calculate time slice for process
    fn calculate_time_slice(&self, process: &Process) -> u32 {
        match process.priority {
            Priority::RealTime(_) => 100_000, // 100ms for RT
            Priority::Normal(_) => {
                // CFS dynamic time slice
                let nr_running = self.cpu_queues.iter()
                    .map(|q| q.cfs_nr_running)
                    .sum::<u32>()
                    .max(1);
                
                let slice = self.sched_latency / nr_running as u64;
                slice.max(self.min_granularity) as u32
            },
            Priority::Idle => 10_000, // 10ms for idle
        }
    }
    
    /// Select CPU for process
    fn select_cpu_for_process(&self, process: &Process, entity: &SchedEntity) -> Result<u32, &'static str> {
        // Check CPU affinity
        if process.cpu_affinity == 0 {
            return Err("No CPUs in affinity mask");
        }
        
        let mut best_cpu = None;
        let mut best_load = u64::MAX;
        
        // Find least loaded CPU that matches affinity
        for (cpu_id, cpu_queue) in self.cpu_queues.iter().enumerate() {
            let cpu_mask = 1u64 << cpu_id;
            if process.cpu_affinity & cpu_mask == 0 {
                continue; // CPU not in affinity mask
            }
            
            // NUMA awareness: prefer same node
            let numa_penalty = if let (Some(process_node), Some(cpu_node)) = 
                (entity.numa_node, cpu_queue.numa_node) {
                if process_node == cpu_node { 0 } else { 100 }
            } else { 0 };
            
            let adjusted_load = cpu_queue.load_avg + numa_penalty;
            
            if adjusted_load < best_load {
                best_load = adjusted_load;
                best_cpu = Some(cpu_id as u32);
            }
        }
        
        best_cpu.ok_or("No suitable CPU found")
    }
    
    /// Perform load balancing
    pub fn load_balance(&mut self) {
        let current_time = crate::time::timestamp_millis();
        let last_balance = self.last_load_balance.load(Ordering::Relaxed);
        
        if current_time - last_balance < self.load_balance_interval {
            return; // Too soon for load balancing
        }
        
        self.last_load_balance.store(current_time, Ordering::Relaxed);
        
        // Find most loaded and least loaded CPUs
        let mut max_load = 0;
        let mut min_load = u64::MAX;
        let mut max_cpu = 0;
        let mut min_cpu = 0;
        
        for (cpu_id, cpu_queue) in self.cpu_queues.iter_mut().enumerate() {
            cpu_queue.update_load_avg();
            let load = cpu_queue.load_avg;
            
            if load > max_load {
                max_load = load;
                max_cpu = cpu_id;
            }
            if load < min_load {
                min_load = load;
                min_cpu = cpu_id;
            }
        }
        
        // If load imbalance is significant, migrate tasks
        if max_load > min_load * 125 / 100 { // 25% imbalance threshold
            self.migrate_tasks(max_cpu as u32, min_cpu as u32);
        }
        
        self.load_balance_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Migrate tasks between CPUs
    fn migrate_tasks(&mut self, from_cpu: u32, to_cpu: u32) {
        if from_cpu >= self.cpu_queues.len() as u32 || to_cpu >= self.cpu_queues.len() as u32 || from_cpu == to_cpu {
            return;
        }
        
        // Get references to the source and destination queues
        let from_idx = from_cpu as usize;
        let to_idx = to_cpu as usize;
        
        // Find a task to migrate from the source CPU
        if let Some((&vruntime, &pid)) = self.cpu_queues[from_idx].cfs_entities.iter().next() {
            if let Some(process) = self.processes.get(&pid) {
                let cpu_mask = 1u64 << to_cpu;
                if process.cpu_affinity & cpu_mask != 0 {
                    // Task can run on target CPU - perform migration
                    if self.cpu_queues[from_idx].cfs_entities.remove(&vruntime).is_some() {
                        self.cpu_queues[from_idx].cfs_nr_running -= 1;
                        self.cpu_queues[to_idx].cfs_entities.insert(vruntime, pid);
                        self.cpu_queues[to_idx].cfs_nr_running += 1;
                        self.migration_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
    
    /// Get scheduler statistics
    pub fn get_stats(&self) -> SchedulerStats {
        let mut total_processes = 0;
        let mut running_processes = 0;
        let mut rt_processes = 0;
        let mut cfs_processes = 0;
        
        for cpu_queue in &self.cpu_queues {
            running_processes += cpu_queue.cfs_nr_running;
            cfs_processes += cpu_queue.cfs_nr_running;
            
            for rt_queue in &cpu_queue.rt_queues {
                rt_processes += rt_queue.len() as u32;
            }
            
            running_processes += rt_processes;
        }
        
        total_processes = self.processes.len() as u32;
        
        SchedulerStats {
            total_processes,
            running_processes,
            rt_processes,
            cfs_processes,
            context_switches: self.total_context_switches.load(Ordering::Relaxed),
            load_balances: self.load_balance_count.load(Ordering::Relaxed),
            migrations: self.migration_count.load(Ordering::Relaxed),
        }
    }
}

/// Scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub total_processes: u32,
    pub running_processes: u32,
    pub rt_processes: u32,
    pub cfs_processes: u32,
    pub context_switches: u64,
    pub load_balances: u64,
    pub migrations: u64,
}

/// Global scheduler instance
static SCHEDULER: Mutex<Option<ProcessScheduler>> = Mutex::new(None);

/// Initialize scheduler
pub fn init_scheduler(nr_cpus: u32) {
    let scheduler = ProcessScheduler::new(nr_cpus);
    *SCHEDULER.lock() = Some(scheduler);
}

/// Get scheduler instance
pub fn get_scheduler() -> Result<spin::MutexGuard<'static, Option<ProcessScheduler>>, &'static str> {
    Ok(SCHEDULER.lock())
}

/// Schedule next task for current CPU
pub fn schedule_current_cpu() -> Option<ProcessId> {
    let current_cpu = 0; // To get actual current CPU
    
    if let Ok(mut sched_guard) = get_scheduler() {
        if let Some(ref mut scheduler) = *sched_guard {
            return scheduler.schedule(current_cpu);
        }
    }
    
    None
}
