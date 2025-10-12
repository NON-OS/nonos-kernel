#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::RwLock;

/// Logical NUMA node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaNode(pub u16);

/// Runtime-configurable NUMA topology:
/// - node_count: number of NUMA nodes
/// - cpu_to_node: mapping from logical CPU id -> node id
#[derive(Debug, Clone)]
pub struct NumaTopology {
    node_count: u16,
    cpu_to_node: Vec<u16>,
}

impl NumaTopology {
    #[inline]
    pub fn new(node_count: u16, cpu_to_node: Vec<u16>) -> Result<Self, &'static str> {
        if node_count == 0 {
            return Err("EINVAL");
        }
        // Validate mapping entries are within node_count
        if !cpu_to_node.iter().all(|&n| (n as u16) < node_count) {
            return Err("EINVAL");
        }
        Ok(Self { node_count, cpu_to_node })
    }

    #[inline]
    pub fn node_count(&self) -> u16 {
        self.node_count
    }

    #[inline]
    pub fn cpu_to_node(&self, cpu_id: u32) -> u16 {
        let idx = cpu_id as usize;
        if idx < self.cpu_to_node.len() {
            self.cpu_to_node[idx]
        } else {
            0
        }
    }
}

// Global topology (defaults to single-node)
static TOPOLOGY: RwLock<NumaTopology> = RwLock::new(NumaTopology {
    node_count: 1,
    cpu_to_node: Vec::new(), // empty means "all CPUs -> node 0"
});

// Provider for current CPU id (set by platform/arch init).
static CURRENT_CPU_ID_PROVIDER: AtomicU32 = AtomicU32::new(u32::MAX);

/// Initialize/replace the global NUMA topology at runtime 
pub fn init_numa_topology(topo: NumaTopology) {
    *TOPOLOGY.write() = topo;
}

/// Set the current-CPU provider for current_node() queries.
/// If unset, current_node() assumes CPU 0.
pub fn set_current_cpu_id(cpu_id: u32) {
    CURRENT_CPU_ID_PROVIDER.store(cpu_id, Ordering::Relaxed);
}

/// Returns number of NUMA nodes currently configured.
#[inline]
pub fn node_count() -> usize {
    TOPOLOGY.read().node_count() as usize
}

/// Returns the NUMA node for a specific CPU id.
#[inline]
pub fn node_of_cpu(cpu_id: u32) -> NumaNode {
    let topo = TOPOLOGY.read();
    NumaNode(topo.cpu_to_node(cpu_id))
}

/// If it hasn't set a CPU id yet, defaults to CPU 0 -> node 0.
#[inline]
pub fn current_node() -> NumaNode {
    let cpu = CURRENT_CPU_ID_PROVIDER.load(Ordering::Relaxed);
    let cpu_id = if cpu == u32::MAX { 0 } else { cpu };
    node_of_cpu(cpu_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn default_single_node() {
        // With default topology, node_count == 1 and all CPUs map to node 0
        assert_eq!(node_count(), 1);
        assert_eq!(current_node(), NumaNode(0));
        assert_eq!(node_of_cpu(123), NumaNode(0));
    }

    #[test]
    fn init_topology_and_query() {
        let topo = NumaTopology::new(2, vec![0, 1, 1, 0]).expect("topo");
        init_numa_topology(topo);
        assert_eq!(node_count(), 2);
        assert_eq!(node_of_cpu(0), NumaNode(0));
        assert_eq!(node_of_cpu(1), NumaNode(1));
        assert_eq!(node_of_cpu(2), NumaNode(1));
        assert_eq!(node_of_cpu(3), NumaNode(0));
        // Non-mapped higher CPUs default to 0
        assert_eq!(node_of_cpu(99), NumaNode(0));
    }

    #[test]
    fn current_cpu_provider() {
        let topo = NumaTopology::new(3, vec![2, 1, 0]).expect("topo");
        init_numa_topology(topo);
        set_current_cpu_id(0);
        assert_eq!(current_node(), NumaNode(2));
        set_current_cpu_id(1);
        assert_eq!(current_node(), NumaNode(1));
        set_current_cpu_id(2);
        assert_eq!(current_node(), NumaNode(0));
    }

    #[test]
    fn validate_inputs() {
        assert!(NumaTopology::new(0, vec![]).is_err());
        assert!(NumaTopology::new(2, vec![0, 2]).is_err()); // 2 is out of range for node_count=2
        assert!(NumaTopology::new(2, vec![0, 1]).is_ok());
    }
}
