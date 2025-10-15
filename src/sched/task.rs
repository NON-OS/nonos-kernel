//! NØNOS Kernel Task

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
    RealTime = 5,
}

#[derive(Debug, Clone)]
pub struct CpuAffinity {
    pub allowed_cpus: alloc::vec::Vec<u32>,
}

impl CpuAffinity {
    pub fn any() -> Self {
        Self { allowed_cpus: (0..16).collect() }
    }
    pub fn new(cpus: alloc::vec::Vec<u32>) -> Self {
        Self { allowed_cpus: cpus }
    }
}

pub struct Task {
    pub name: &'static str,
    pub func: fn(),
    pub priority: Priority,
    pub affinity: CpuAffinity,
    pub complete: bool,
}

impl Task {
    pub fn run(&mut self) {
        (self.func)();
        self.complete = true;
    }
    pub fn is_complete(&self) -> bool {
        self.complete
    }
    pub fn spawn(name: &'static str, func: fn(), priority: Priority, affinity: CpuAffinity) -> Self {
        Self {
            name,
            func,
            priority,
            affinity,
            complete: false,
        }
    }
}
