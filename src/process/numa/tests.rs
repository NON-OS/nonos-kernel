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
