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

//! Node state management.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::RwLock;

use super::config::NodeConfig;
use super::peers::PeerInfo;
use super::sync::SyncStatus;

static NODE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static NODE_RUNNING: AtomicBool = AtomicBool::new(false);
static NODE_STATE: RwLock<Option<NodeStateInner>> = RwLock::new(None);
static START_TIME: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Stopped,
    Starting,
    Syncing,
    Running,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Light,
    Full,
    Archive,
}

struct NodeStateInner {
    config: NodeConfig,
    status: NodeStatus,
    node_type: NodeType,
    peers: Vec<PeerInfo>,
    sync_status: SyncStatus,
    current_block: u64,
    highest_block: u64,
    peer_count: usize,
    error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NodeState {
    pub status: NodeStatus,
    pub node_type: NodeType,
    pub current_block: u64,
    pub highest_block: u64,
    pub peer_count: usize,
    pub sync_progress: f64,
    pub uptime_secs: u64,
    pub is_synced: bool,
    pub error_message: Option<String>,
}

impl NodeState {
    pub fn sync_percentage(&self) -> f64 {
        self.sync_progress * 100.0
    }

    pub fn blocks_behind(&self) -> u64 {
        self.highest_block.saturating_sub(self.current_block)
    }

    pub fn uptime_formatted(&self) -> String {
        let secs = self.uptime_secs;
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let seconds = secs % 60;
        alloc::format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

pub fn init(config: NodeConfig) {
    if NODE_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    let inner = NodeStateInner {
        config,
        status: NodeStatus::Stopped,
        node_type: NodeType::Light,
        peers: Vec::new(),
        sync_status: SyncStatus::new(),
        current_block: 0,
        highest_block: 0,
        peer_count: 0,
        error_message: None,
    };

    {
        let mut guard = NODE_STATE.write();
        *guard = Some(inner);
    }

    NODE_INITIALIZED.store(true, Ordering::SeqCst);
}

pub fn is_initialized() -> bool {
    NODE_INITIALIZED.load(Ordering::SeqCst)
}

pub fn is_running() -> bool {
    NODE_RUNNING.load(Ordering::SeqCst)
}

pub fn get_state() -> Option<NodeState> {
    if !NODE_INITIALIZED.load(Ordering::SeqCst) {
        return None;
    }

    let guard = NODE_STATE.read();
    let inner = guard.as_ref()?;

    let sync_progress = if inner.highest_block > 0 {
        inner.current_block as f64 / inner.highest_block as f64
    } else {
        0.0
    };

    let uptime = if NODE_RUNNING.load(Ordering::Relaxed) {
        let start = START_TIME.load(Ordering::Relaxed);
        crate::time::timestamp_secs().saturating_sub(start)
    } else {
        0
    };

    Some(NodeState {
        status: inner.status,
        node_type: inner.node_type,
        current_block: inner.current_block,
        highest_block: inner.highest_block,
        peer_count: inner.peer_count,
        sync_progress,
        uptime_secs: uptime,
        is_synced: inner.current_block >= inner.highest_block && inner.highest_block > 0,
        error_message: inner.error_message.clone(),
    })
}

pub fn start() -> Result<(), &'static str> {
    if !NODE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("Node not initialized");
    }

    if NODE_RUNNING.load(Ordering::SeqCst) {
        return Err("Node already running");
    }

    {
        let mut guard = NODE_STATE.write();
        if let Some(inner) = guard.as_mut() {
            inner.status = NodeStatus::Starting;
            inner.error_message = None;
        }
    }

    START_TIME.store(crate::time::timestamp_secs(), Ordering::SeqCst);
    NODE_RUNNING.store(true, Ordering::SeqCst);

    {
        let mut guard = NODE_STATE.write();
        if let Some(inner) = guard.as_mut() {
            inner.status = NodeStatus::Syncing;
        }
    }

    Ok(())
}

pub fn stop() -> Result<(), &'static str> {
    if !NODE_RUNNING.load(Ordering::SeqCst) {
        return Err("Node not running");
    }

    NODE_RUNNING.store(false, Ordering::SeqCst);

    {
        let mut guard = NODE_STATE.write();
        if let Some(inner) = guard.as_mut() {
            inner.status = NodeStatus::Stopped;
            inner.peers.clear();
            inner.peer_count = 0;
        }
    }

    Ok(())
}

pub fn set_status(status: NodeStatus) {
    let mut guard = NODE_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.status = status;
    }
}

pub fn set_error(message: &str) {
    let mut guard = NODE_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.status = NodeStatus::Error;
        inner.error_message = Some(String::from(message));
    }
}

pub fn update_block_height(current: u64, highest: u64) {
    let mut guard = NODE_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.current_block = current;
        inner.highest_block = highest;

        if current >= highest && highest > 0 {
            inner.status = NodeStatus::Running;
        }
    }
}

pub fn update_peer_count(count: usize) {
    let mut guard = NODE_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.peer_count = count;
    }
}

pub fn set_node_type(node_type: NodeType) {
    let mut guard = NODE_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.node_type = node_type;
    }
}

pub fn get_current_block() -> u64 {
    let guard = NODE_STATE.read();
    guard.as_ref().map(|i| i.current_block).unwrap_or(0)
}

pub fn get_highest_block() -> u64 {
    let guard = NODE_STATE.read();
    guard.as_ref().map(|i| i.highest_block).unwrap_or(0)
}

pub fn get_config() -> Option<NodeConfig> {
    let guard = NODE_STATE.read();
    guard.as_ref().map(|i| i.config.clone())
}

pub fn get_sync_status() -> Option<SyncStatus> {
    let guard = NODE_STATE.read();
    guard.as_ref().map(|i| i.sync_status.clone())
}

pub fn update_sync_status(status: SyncStatus) {
    let mut guard = NODE_STATE.write();
    if let Some(inner) = guard.as_mut() {
        inner.sync_status = status;
    }
}
