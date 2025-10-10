//! Advanced Process Control Block
//!
//! Comprehensive process representation with advanced features

use crate::process::{capabilities::CapabilitySet, numa::NumaNode};
use crate::security::NonosCapability;
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{structures::paging::PageTableFlags, VirtAddr};

/// Process identifier
pub type ProcessId = u64;

/// Thread identifier  
pub type ThreadId = u64;

/// Process states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessState {
    Created,    // Just created, not scheduled
    Ready,      // Ready to run
    Running,    // Currently executing
    Blocked,    // Waiting for resource
    Suspended,  // Swapped out or suspended
    Zombie,     // Terminated but not reaped
    Terminated, // Fully terminated
}

/// Process priority levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Priority {
    RealTime(u8), // RT priority 0-99
    Normal(i8),   // Normal priority -20 to 19
    Idle,         // Idle/background
}

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_addr: VirtAddr,
    pub size: usize,
    pub flags: PageTableFlags,
    pub name: String,
    pub file_backed: Option<String>, // Path to backing file
    pub copy_on_write: bool,
    pub shared: bool,
}

/// File descriptor entry
#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub fd_number: u32,
    pub file_path: String,
    pub flags: u32,
    pub offset: u64,
    pub ref_count: u32,
}

/// Advanced Process Control Block
pub struct Process {
    // Core identification
    pub pid: ProcessId,
    pub parent_pid: Option<ProcessId>,
    pub process_group_id: ProcessId,
    pub session_id: ProcessId,

    // Process state
    pub state: ProcessState,
    pub priority: Priority,
    pub nice_value: i8,
    pub rt_priority: u8,

    // Threads (this process can have multiple threads)
    pub threads: Vec<ThreadId>,
    pub main_thread: ThreadId,

    // Memory management
    pub memory_regions: Vec<MemoryRegion>,
    pub heap_start: VirtAddr,
    pub heap_end: VirtAddr,
    pub stack_start: VirtAddr,
    pub stack_end: VirtAddr,
    pub total_memory_usage: usize,
    pub peak_memory_usage: usize,

    // File system
    pub current_directory: String,
    pub file_descriptors: BTreeMap<u32, FileDescriptor>,
    pub next_fd: u32,

    // Security and capabilities
    pub capabilities: CapabilitySet,
    pub user_id: u32,
    pub group_id: u32,
    pub effective_user_id: u32,
    pub effective_group_id: u32,
    pub saved_user_id: u32,
    pub saved_group_id: u32,

    // NUMA and affinity
    pub numa_node: Option<NumaNode>,
    pub cpu_affinity: u64, // Bitmask of allowed CPUs
    pub last_cpu: u32,
    pub numa_policy: NumaPolicy,

    // Scheduling statistics
    pub creation_time: u64,
    pub total_runtime: AtomicU64,
    pub voluntary_context_switches: AtomicU64,
    pub involuntary_context_switches: AtomicU64,
    pub last_scheduled: u64,
    pub time_slice_remaining: u32,

    // Resource limits
    pub limits: ResourceLimits,

    // Signal handling
    pub signal_mask: u64,
    pub pending_signals: u64,
    pub signal_handlers: BTreeMap<u32, VirtAddr>,

    // Advanced features
    pub is_real_time: bool,
    pub real_time_deadline: Option<u64>,
    pub control_group: Option<String>, // cgroup path
    pub container_id: Option<String>,
    pub security_context: String,

    // Performance counters
    pub page_faults: AtomicU64,
    pub cache_misses: AtomicU64,
    pub syscall_count: AtomicU64,

    // Process tree
    pub children: Vec<ProcessId>,

    // Exit information
    pub exit_code: Option<i32>,
    pub exit_signal: Option<u32>,
}

/// NUMA memory allocation policy
#[derive(Debug, Clone, Copy)]
pub enum NumaPolicy {
    Default,        // System default
    Bind(u32),      // Bind to specific node
    Interleave,     // Interleave across nodes
    Preferred(u32), // Prefer node but allow others
}

/// Resource limits
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_memory: usize,
    pub max_cpu_time: u64,
    pub max_file_descriptors: u32,
    pub max_stack_size: usize,
    pub max_heap_size: usize,
    pub max_threads: u32,
    pub max_files: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory: 1024 * 1024 * 1024, // 1GB
            max_cpu_time: u64::MAX,
            max_file_descriptors: 1024,
            max_stack_size: 8 * 1024 * 1024,  // 8MB
            max_heap_size: 512 * 1024 * 1024, // 512MB
            max_threads: 1024,
            max_files: 65536,
        }
    }
}

impl Process {
    /// Create new process
    pub fn new(pid: ProcessId, parent_pid: Option<ProcessId>) -> Self {
        let creation_time = crate::time::timestamp_millis();

        Process {
            pid,
            parent_pid,
            process_group_id: pid, // Initially same as PID
            session_id: pid,

            state: ProcessState::Created,
            priority: Priority::Normal(0),
            nice_value: 0,
            rt_priority: 0,

            threads: Vec::new(),
            main_thread: 0,

            memory_regions: Vec::new(),
            heap_start: VirtAddr::new(0x600000000000),
            heap_end: VirtAddr::new(0x600000000000),
            stack_start: VirtAddr::new(0x700000000000),
            stack_end: VirtAddr::new(0x700000010000), // 64KB initial stack
            total_memory_usage: 0,
            peak_memory_usage: 0,

            current_directory: String::from("/"),
            file_descriptors: BTreeMap::new(),
            next_fd: 3, // 0,1,2 reserved for stdin,stdout,stderr

            capabilities: CapabilitySet::new_user(),
            user_id: 1000,
            group_id: 1000,
            effective_user_id: 1000,
            effective_group_id: 1000,
            saved_user_id: 1000,
            saved_group_id: 1000,

            numa_node: None,
            cpu_affinity: u64::MAX, // All CPUs allowed initially
            last_cpu: 0,
            numa_policy: NumaPolicy::Default,

            creation_time,
            total_runtime: AtomicU64::new(0),
            voluntary_context_switches: AtomicU64::new(0),
            involuntary_context_switches: AtomicU64::new(0),
            last_scheduled: 0,
            time_slice_remaining: 0,

            limits: ResourceLimits::default(),

            signal_mask: 0,
            pending_signals: 0,
            signal_handlers: BTreeMap::new(),

            is_real_time: false,
            real_time_deadline: None,
            control_group: None,
            container_id: None,
            security_context: String::from("unconfined"),

            page_faults: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            syscall_count: AtomicU64::new(0),

            children: Vec::new(),

            exit_code: None,
            exit_signal: None,
        }
    }

    /// Add memory region
    pub fn add_memory_region(&mut self, region: MemoryRegion) -> Result<(), &'static str> {
        // Check against resource limits
        let new_total = self.total_memory_usage + region.size;
        if new_total > self.limits.max_memory {
            return Err("Memory limit exceeded");
        }

        // Check for overlaps
        for existing in &self.memory_regions {
            let existing_end = existing.start_addr + existing.size as u64;
            let new_end = region.start_addr + region.size as u64;

            if (region.start_addr >= existing.start_addr && region.start_addr < existing_end)
                || (new_end > existing.start_addr && new_end <= existing_end)
            {
                return Err("Memory region overlaps with existing region");
            }
        }

        self.total_memory_usage = new_total;
        if new_total > self.peak_memory_usage {
            self.peak_memory_usage = new_total;
        }

        self.memory_regions.push(region);
        Ok(())
    }

    /// Open file descriptor
    pub fn open_file(&mut self, path: String, flags: u32) -> Result<u32, &'static str> {
        if self.file_descriptors.len() >= self.limits.max_file_descriptors as usize {
            return Err("Too many open files");
        }

        let fd = self.next_fd;
        self.next_fd += 1;

        let file_desc =
            FileDescriptor { fd_number: fd, file_path: path, flags, offset: 0, ref_count: 1 };

        self.file_descriptors.insert(fd, file_desc);
        Ok(fd)
    }

    /// Check if process has capability
    pub fn has_capability(&self, capability: NonosCapability) -> bool {
        // Check process-level capabilities first
        if self.capabilities.has_capability(&format!("{:?}", capability)) {
            return true;
        }

        // Check with capability engine for isolation chamber capabilities
        if let Some(engine) = crate::security::get_capability_engine() {
            if let Ok(has_cap) = engine.check_capability(self.pid, capability) {
                return has_cap;
            }
        }

        false
    }

    /// Get process ID
    pub fn get_pid(&self) -> ProcessId {
        self.pid
    }

    /// Close file descriptor
    pub fn close_file(&mut self, fd: u32) -> Result<(), &'static str> {
        if let Some(mut file_desc) = self.file_descriptors.remove(&fd) {
            file_desc.ref_count -= 1;
            if file_desc.ref_count > 0 {
                self.file_descriptors.insert(fd, file_desc);
            }
            Ok(())
        } else {
            Err("Invalid file descriptor")
        }
    }

    /// Set process priority
    pub fn set_priority(&mut self, priority: Priority) -> Result<(), &'static str> {
        match priority {
            Priority::RealTime(rt_prio) => {
                if !self.capabilities.has_capability("CAP_SYS_NICE") {
                    return Err("Insufficient privileges for real-time priority");
                }
                self.is_real_time = true;
                self.rt_priority = rt_prio;
            }
            Priority::Normal(nice) => {
                if nice < 0 && !self.capabilities.has_capability("CAP_SYS_NICE") {
                    return Err("Insufficient privileges for negative nice value");
                }
                self.nice_value = nice;
                self.is_real_time = false;
            }
            Priority::Idle => {
                self.is_real_time = false;
            }
        }

        self.priority = priority;
        Ok(())
    }

    /// Get process statistics
    pub fn get_stats(&self) -> ProcessStats {
        ProcessStats {
            pid: self.pid,
            state: self.state,
            priority: self.priority,
            memory_usage: self.total_memory_usage,
            peak_memory: self.peak_memory_usage,
            cpu_time: self.total_runtime.load(Ordering::Relaxed),
            page_faults: self.page_faults.load(Ordering::Relaxed),
            context_switches: self.voluntary_context_switches.load(Ordering::Relaxed)
                + self.involuntary_context_switches.load(Ordering::Relaxed),
            open_files: self.file_descriptors.len(),
            threads: self.threads.len(),
        }
    }

    /// Check if process can access resource
    pub fn can_access_resource(&self, resource: &str) -> bool {
        self.capabilities.has_capability(resource)
    }

    /// Set NUMA affinity
    pub fn set_numa_policy(&mut self, policy: NumaPolicy) -> Result<(), &'static str> {
        if !self.capabilities.has_capability("CAP_SYS_NICE") {
            return Err("Insufficient privileges for NUMA policy");
        }

        self.numa_policy = policy;
        Ok(())
    }
}

/// Process statistics for monitoring
#[derive(Debug, Clone)]
pub struct ProcessStats {
    pub pid: ProcessId,
    pub state: ProcessState,
    pub priority: Priority,
    pub memory_usage: usize,
    pub peak_memory: usize,
    pub cpu_time: u64,
    pub page_faults: u64,
    pub context_switches: u64,
    pub open_files: usize,
    pub threads: usize,
}

// Global process management
use spin::RwLock;
static PROCESS_TABLE: RwLock<BTreeMap<ProcessId, Process>> = RwLock::new(BTreeMap::new());
static CURRENT_PROCESS_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_PID: AtomicU64 = AtomicU64::new(2);

/// Get the current process ID
pub fn get_current_process_id() -> Option<ProcessId> {
    let current = CURRENT_PROCESS_ID.load(Ordering::Acquire);
    if current == 0 {
        None
    } else {
        Some(current)
    }
}

/// Set the current process ID
pub fn set_current_process_id(pid: ProcessId) {
    CURRENT_PROCESS_ID.store(pid, Ordering::Release);
}

/// Allocate new process ID
pub fn allocate_pid() -> ProcessId {
    NEXT_PID.fetch_add(1, Ordering::Release)
}

/// Create a new process
pub fn create_process(parent_pid: Option<ProcessId>) -> Result<ProcessId, &'static str> {
    let pid = allocate_pid();
    let process = Process::new(pid, parent_pid);

    PROCESS_TABLE.write().insert(pid, process);
    Ok(pid)
}

/// Get process by PID (returns PID for safety due to non-cloneable Process)
pub fn get_process_pid(pid: ProcessId) -> Option<ProcessId> {
    PROCESS_TABLE.read().get(&pid).map(|p| p.pid)
}

/// Get current process PID (safer approach)
pub fn get_current_process_pid() -> Option<ProcessId> {
    get_current_process_id()
}

/// Check if current process has capability
pub fn current_process_has_capability(capability: NonosCapability) -> bool {
    if let Some(pid) = get_current_process_id() {
        PROCESS_TABLE
            .read()
            .get(&pid)
            .map(|process| process.has_capability(capability))
            .unwrap_or(false)
    } else {
        false
    }
}

/// Remove process from table
pub fn remove_process(pid: ProcessId) -> Option<Process> {
    PROCESS_TABLE.write().remove(&pid)
}
