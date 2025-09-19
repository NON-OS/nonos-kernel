//! NUMA (Non-Uniform Memory Access) Management
//!
//! Advanced NUMA topology detection and memory allocation policies

use alloc::{vec::Vec, vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use x86_64::PhysAddr;

/// NUMA node identifier
pub type NumaNodeId = u32;

/// NUMA node information
#[derive(Debug)]
pub struct NumaNode {
    pub node_id: NumaNodeId,
    pub cpu_mask: u64,         // CPUs belonging to this node
    pub memory_start: PhysAddr,
    pub memory_size: usize,
    pub memory_free: AtomicUsize,
    pub memory_used: AtomicUsize,
    pub distance_map: Vec<u32>, // Distance to other nodes
}

/// NUMA topology manager
pub struct NumaTopology {
    nodes: Vec<NumaNode>,
    node_map: BTreeMap<NumaNodeId, usize>, // Node ID to index mapping
    total_nodes: u32,
    
    // Statistics
    cross_node_allocations: AtomicU64,
    local_allocations: AtomicU64,
    migration_count: AtomicU64,
}

impl NumaTopology {
    /// Create new NUMA topology
    pub fn new() -> Self {
        NumaTopology {
            nodes: Vec::new(),
            node_map: BTreeMap::new(),
            total_nodes: 0,
            cross_node_allocations: AtomicU64::new(0),
            local_allocations: AtomicU64::new(0),
            migration_count: AtomicU64::new(0),
        }
    }
    
    /// Detect NUMA topology from hardware
    pub fn detect_topology() -> Self {
        let mut topology = NumaTopology::new();
        
        // Parse ACPI SRAT (System Resource Affinity Table) for real topology
        if let Some(acpi_tables) = crate::arch::x86_64::acpi::get_acpi_tables() {
            if let Some(srat) = acpi_tables.find_table::<crate::arch::x86_64::acpi::Srat>() {
                // Parse SRAT entries to build actual NUMA topology
                for entry in srat.entries() {
                    match entry {
                        crate::arch::x86_64::acpi::SratEntry::ProcessorAffinity(cpu_affinity) => {
                            let node_id = cpu_affinity.proximity_domain_low as u32;
                            topology.associate_cpu_with_node(cpu_affinity.local_apic_id as u32, node_id);
                        },
                        crate::arch::x86_64::acpi::SratEntry::MemoryAffinity(mem_affinity) => {
                            let node_id = mem_affinity.proximity_domain;
                            let base_addr = PhysAddr::new(mem_affinity.base_address);
                            let size = mem_affinity.length_bytes;
                            topology.add_memory_range_to_node(node_id, base_addr, size);
                        },
                        crate::arch::x86_64::acpi::SratEntry::ProcessorX2ApicAffinity(x2apic_affinity) => {
                            let node_id = x2apic_affinity.proximity_domain;
                            topology.associate_cpu_with_node(x2apic_affinity.x2apic_id, node_id);
                        }
                    }
                }
            }
        } else {
            crate::log_warn!("ACPI not available, using fallback NUMA topology");
        }
        
        // If no ACPI, create reasonable fallback topology
        topology.add_node(NumaNode {
            node_id: 0,
            cpu_mask: 0x0F, // CPUs 0-3
            memory_start: PhysAddr::new(0x100000),
            memory_size: 512 * 1024 * 1024, // 512MB
            memory_free: AtomicUsize::new(512 * 1024 * 1024),
            memory_used: AtomicUsize::new(0),
            distance_map: vec![10, 20], // 10 = local, 20 = remote
        });
        
        topology.add_node(NumaNode {
            node_id: 1,
            cpu_mask: 0xF0, // CPUs 4-7
            memory_start: PhysAddr::new(0x40000000), // 1GB
            memory_size: 512 * 1024 * 1024,
            memory_free: AtomicUsize::new(512 * 1024 * 1024),
            memory_used: AtomicUsize::new(0),
            distance_map: vec![20, 10],
        });
        
        topology
    }
    
    /// Add NUMA node to topology
    pub fn add_node(&mut self, node: NumaNode) {
        let node_id = node.node_id;
        let index = self.nodes.len();
        
        self.nodes.push(node);
        self.node_map.insert(node_id, index);
        self.total_nodes += 1;
    }
    
    /// Get node by ID
    pub fn get_node(&self, node_id: NumaNodeId) -> Option<&NumaNode> {
        self.node_map.get(&node_id)
            .and_then(|&index| self.nodes.get(index))
    }
    
    /// Get node by CPU
    pub fn node_for_cpu(&self, cpu_id: u32) -> Option<NumaNodeId> {
        let cpu_mask = 1u64 << cpu_id;
        
        for node in &self.nodes {
            if node.cpu_mask & cpu_mask != 0 {
                return Some(node.node_id);
            }
        }
        
        None
    }
    
    /// Find best node for allocation
    pub fn best_node_for_allocation(&self, current_cpu: u32, size: usize, policy: NumaAllocationPolicy) -> Option<NumaNodeId> {
        match policy {
            NumaAllocationPolicy::Local => {
                // Try current CPU's node first
                if let Some(node_id) = self.node_for_cpu(current_cpu) {
                    if let Some(node) = self.get_node(node_id) {
                        if node.memory_free.load(Ordering::Relaxed) >= size {
                            return Some(node_id);
                        }
                    }
                }
                None
            },
            
            NumaAllocationPolicy::Interleave => {
                // Round-robin across nodes
                let preferred_node = (current_cpu as NumaNodeId) % self.total_nodes;
                
                // Try preferred node first, then others
                for offset in 0..self.total_nodes {
                    let node_id = (preferred_node + offset) % self.total_nodes;
                    if let Some(node) = self.get_node(node_id) {
                        if node.memory_free.load(Ordering::Relaxed) >= size {
                            return Some(node_id);
                        }
                    }
                }
                None
            },
            
            NumaAllocationPolicy::Preferred(preferred_node) => {
                // Try preferred node first
                if let Some(node) = self.get_node(preferred_node) {
                    if node.memory_free.load(Ordering::Relaxed) >= size {
                        return Some(preferred_node);
                    }
                }
                
                // Fall back to any available node
                for node in &self.nodes {
                    if node.memory_free.load(Ordering::Relaxed) >= size {
                        return Some(node.node_id);
                    }
                }
                None
            },
            
            NumaAllocationPolicy::Bind(bound_node) => {
                // Must use specific node
                if let Some(node) = self.get_node(bound_node) {
                    if node.memory_free.load(Ordering::Relaxed) >= size {
                        return Some(bound_node);
                    }
                }
                None
            }
        }
    }
    
    /// Allocate memory on specific node
    pub fn allocate_on_node(&mut self, node_id: NumaNodeId, size: usize) -> Result<PhysAddr, &'static str> {
        if let Some(index) = self.node_map.get(&node_id).copied() {
            if let Some(node) = self.nodes.get_mut(index) {
                let available = node.memory_free.load(Ordering::Relaxed);
                if available >= size {
                    node.memory_free.fetch_sub(size, Ordering::Relaxed);
                    node.memory_used.fetch_add(size, Ordering::Relaxed);
                    
                    // Calculate allocation address (simplified)
                    let used = node.memory_used.load(Ordering::Relaxed) - size;
                    let addr = node.memory_start + used as u64;
                    
                    // Update statistics
                    if self.node_for_cpu(0) == Some(node_id) { // Simplified CPU check
                        self.local_allocations.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.cross_node_allocations.fetch_add(1, Ordering::Relaxed);
                    }
                    
                    return Ok(addr);
                }
            }
        }
        
        Err("Cannot allocate on requested NUMA node")
    }
    
    /// Get distance between nodes
    pub fn node_distance(&self, from: NumaNodeId, to: NumaNodeId) -> Option<u32> {
        if let Some(node) = self.get_node(from) {
            node.distance_map.get(to as usize).copied()
        } else {
            None
        }
    }
    
    /// Find closest node with available memory
    pub fn closest_available_node(&self, from: NumaNodeId, size: usize) -> Option<NumaNodeId> {
        let mut best_node = None;
        let mut best_distance = u32::MAX;
        
        for node in &self.nodes {
            if node.memory_free.load(Ordering::Relaxed) >= size {
                if let Some(distance) = self.node_distance(from, node.node_id) {
                    if distance < best_distance {
                        best_distance = distance;
                        best_node = Some(node.node_id);
                    }
                }
            }
        }
        
        best_node
    }
    
    /// Get NUMA statistics
    pub fn get_stats(&self) -> NumaStats {
        let mut total_memory = 0;
        let mut total_free = 0;
        let mut total_used = 0;
        
        for node in &self.nodes {
            total_memory += node.memory_size;
            total_free += node.memory_free.load(Ordering::Relaxed);
            total_used += node.memory_used.load(Ordering::Relaxed);
        }
        
        NumaStats {
            total_nodes: self.total_nodes,
            total_memory,
            total_free,
            total_used,
            local_allocations: self.local_allocations.load(Ordering::Relaxed),
            cross_node_allocations: self.cross_node_allocations.load(Ordering::Relaxed),
            migration_count: self.migration_count.load(Ordering::Relaxed),
        }
    }
    
    /// Balance memory across nodes
    pub fn balance_memory(&mut self) -> Result<u32, &'static str> {
        let stats = self.get_stats();
        let average_usage = stats.total_used / self.total_nodes as usize;
        let mut migrations = 0;
        
        // Simple balancing algorithm - collect node info first to avoid double borrow
        let node_info: Vec<(u32, usize)> = self.nodes.iter()
            .map(|node| (node.node_id, node.memory_used.load(Ordering::Relaxed)))
            .collect();
        
        for (node_id, current_usage) in node_info {
            if current_usage > average_usage * 110 / 100 { // 10% above average
                // This node is overloaded, try to migrate some memory
                let excess = current_usage - average_usage;
                
                // Find underutilized node
                for target_node in &self.nodes {
                    if target_node.node_id != node_id {
                        let target_usage = target_node.memory_used.load(Ordering::Relaxed);
                        if target_usage < average_usage * 90 / 100 { // 10% below average
                            // Simulate migration (in real implementation, would move pages)
                            let migrate_size = excess.min(average_usage - target_usage);
                            
                            // Find source node and update it
                            if let Some(source_node) = self.nodes.iter().find(|n| n.node_id == node_id) {
                                source_node.memory_used.fetch_sub(migrate_size, Ordering::Relaxed);
                                source_node.memory_free.fetch_add(migrate_size, Ordering::Relaxed);
                            }
                            
                            target_node.memory_used.fetch_add(migrate_size, Ordering::Relaxed);
                            target_node.memory_free.fetch_sub(migrate_size, Ordering::Relaxed);
                            
                            migrations += 1;
                            self.migration_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(migrations)
    }

    /// Associate a CPU with a NUMA node
    pub fn associate_cpu_with_node(&mut self, cpu_id: u32, node_id: u32) {
        // Find or create node
        if let Some(node_index) = self.node_map.get(&node_id).cloned() {
            // Add CPU to existing node's mask
            self.nodes[node_index].cpu_mask |= 1u64 << cpu_id;
        } else {
            // Create new node
            let new_node = NumaNode {
                node_id,
                cpu_mask: 1u64 << cpu_id,
                memory_start: PhysAddr::new(0),
                memory_size: 0,
                memory_free: AtomicUsize::new(0),
                memory_used: AtomicUsize::new(0),
                distance_map: Vec::new(),
            };
            
            let node_index = self.nodes.len();
            self.nodes.push(new_node);
            self.node_map.insert(node_id, node_index);
            self.total_nodes += 1;
        }
    }

    /// Add a memory range to a NUMA node
    pub fn add_memory_range_to_node(&mut self, node_id: u32, base_addr: PhysAddr, size: u64) {
        // Find or create node
        if let Some(node_index) = self.node_map.get(&node_id).cloned() {
            // Update existing node's memory info (simplified - assumes single contiguous range)
            if self.nodes[node_index].memory_size == 0 {
                self.nodes[node_index].memory_start = base_addr;
            }
            self.nodes[node_index].memory_size += size as usize;
            self.nodes[node_index].memory_free.fetch_add(size as usize, Ordering::Relaxed);
        } else {
            // Create new node with memory range
            let new_node = NumaNode {
                node_id,
                cpu_mask: 0,
                memory_start: base_addr,
                memory_size: size as usize,
                memory_free: AtomicUsize::new(size as usize),
                memory_used: AtomicUsize::new(0),
                distance_map: Vec::new(),
            };
            
            let node_index = self.nodes.len();
            self.nodes.push(new_node);
            self.node_map.insert(node_id, node_index);
            self.total_nodes += 1;
        }
    }
}

/// NUMA allocation policy
#[derive(Debug, Clone, Copy)]
pub enum NumaAllocationPolicy {
    Local,              // Allocate on local node
    Interleave,         // Interleave across all nodes
    Preferred(NumaNodeId), // Prefer specific node, fall back to others
    Bind(NumaNodeId),   // Bind to specific node only
}

/// NUMA statistics
#[derive(Debug, Clone)]
pub struct NumaStats {
    pub total_nodes: u32,
    pub total_memory: usize,
    pub total_free: usize,
    pub total_used: usize,
    pub local_allocations: u64,
    pub cross_node_allocations: u64,
    pub migration_count: u64,
}

/// Global NUMA topology instance
static mut NUMA_TOPOLOGY: Option<NumaTopology> = None;

/// Initialize NUMA subsystem
pub fn init_numa() {
    let topology = NumaTopology::detect_topology();
    unsafe {
        NUMA_TOPOLOGY = Some(topology);
    }
}

/// Get current NUMA topology
pub fn get_topology() -> Option<&'static NumaTopology> {
    unsafe { NUMA_TOPOLOGY.as_ref() }
}

/// Get mutable NUMA topology
pub fn get_topology_mut() -> Option<&'static mut NumaTopology> {
    unsafe { NUMA_TOPOLOGY.as_mut() }
}