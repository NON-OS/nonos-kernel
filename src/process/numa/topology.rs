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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::RwLock;

use super::types::{NumaNode, NumaTopology};

// Global topology (defaults to single-node)
static TOPOLOGY: RwLock<NumaTopology> = RwLock::new(NumaTopology {
    node_count: 1,
    cpu_to_node: Vec::new(), // empty means "all CPUs -> node 0"
});

// Provider for current CPU id (set by platform/arch init).
static CURRENT_CPU_ID_PROVIDER: AtomicU32 = AtomicU32::new(u32::MAX);

pub fn init_numa_topology(topo: NumaTopology) {
    *TOPOLOGY.write() = topo;
}

pub fn set_current_cpu_id(cpu_id: u32) {
    CURRENT_CPU_ID_PROVIDER.store(cpu_id, Ordering::Relaxed);
}

#[inline]
pub fn node_count() -> usize {
    TOPOLOGY.read().node_count() as usize
}

#[inline]
pub fn node_of_cpu(cpu_id: u32) -> NumaNode {
    let topo = TOPOLOGY.read();
    NumaNode(topo.cpu_to_node(cpu_id))
}

#[inline]
pub fn current_node() -> NumaNode {
    let cpu = CURRENT_CPU_ID_PROVIDER.load(Ordering::Relaxed);
    let cpu_id = if cpu == u32::MAX { 0 } else { cpu };
    node_of_cpu(cpu_id)
}
