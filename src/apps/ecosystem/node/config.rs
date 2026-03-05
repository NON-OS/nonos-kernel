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

//! Node configuration.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use spin::RwLock;

static NODE_CONFIG: RwLock<Option<NodeConfig>> = RwLock::new(None);

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub sync: SyncConfig,
    pub rpc: RpcConfig,
    pub discovery: DiscoveryConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            sync: SyncConfig::default(),
            rpc: RpcConfig::default(),
            discovery: DiscoveryConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub network_id: u64,
    pub listen_port: u16,
    pub max_peers: usize,
    pub bootnodes: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            chain_id: 11155111,
            network_id: 11155111,
            listen_port: 30303,
            max_peers: 25,
            bootnodes: alloc::vec![
                String::from("enode://...@bootnode1.sepolia.io:30303"),
                String::from("enode://...@bootnode2.sepolia.io:30303"),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub mode: SyncMode,
    pub fast_sync: bool,
    pub snap_sync: bool,
    pub light_serve: bool,
    pub max_block_download: u32,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            mode: SyncMode::Light,
            fast_sync: true,
            snap_sync: true,
            light_serve: false,
            max_block_download: 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    Full,
    Fast,
    Light,
    Snap,
}

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub enabled_apis: Vec<String>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: String::from("127.0.0.1"),
            port: 8545,
            cors_origins: alloc::vec![String::from("*")],
            enabled_apis: alloc::vec![
                String::from("eth"),
                String::from("net"),
                String::from("web3"),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub dns_discovery: bool,
    pub static_nodes: Vec<String>,
    pub trusted_nodes: Vec<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dns_discovery: true,
            static_nodes: Vec::new(),
            trusted_nodes: Vec::new(),
        }
    }
}

pub fn get_config() -> NodeConfig {
    let guard = NODE_CONFIG.read();
    guard.clone().unwrap_or_default()
}

pub fn set_config(config: NodeConfig) {
    let mut guard = NODE_CONFIG.write();
    *guard = Some(config);
}

pub fn update_network_config<F>(f: F)
where
    F: FnOnce(&mut NetworkConfig),
{
    let mut guard = NODE_CONFIG.write();
    if let Some(config) = guard.as_mut() {
        f(&mut config.network);
    }
}

pub fn update_sync_config<F>(f: F)
where
    F: FnOnce(&mut SyncConfig),
{
    let mut guard = NODE_CONFIG.write();
    if let Some(config) = guard.as_mut() {
        f(&mut config.sync);
    }
}

pub fn update_rpc_config<F>(f: F)
where
    F: FnOnce(&mut RpcConfig),
{
    let mut guard = NODE_CONFIG.write();
    if let Some(config) = guard.as_mut() {
        f(&mut config.rpc);
    }
}

pub fn set_chain_id(chain_id: u64) {
    update_network_config(|net| {
        net.chain_id = chain_id;
        net.network_id = chain_id;
    });
}

pub fn set_max_peers(max_peers: usize) {
    update_network_config(|net| {
        net.max_peers = max_peers;
    });
}

pub fn set_sync_mode(mode: SyncMode) {
    update_sync_config(|sync| {
        sync.mode = mode;
    });
}

pub fn enable_rpc(enabled: bool) {
    update_rpc_config(|rpc| {
        rpc.enabled = enabled;
    });
}

pub fn add_bootnode(enode: &str) {
    let mut guard = NODE_CONFIG.write();
    if let Some(config) = guard.as_mut() {
        config.network.bootnodes.push(String::from(enode));
    }
}

pub fn add_static_node(enode: &str) {
    let mut guard = NODE_CONFIG.write();
    if let Some(config) = guard.as_mut() {
        config.discovery.static_nodes.push(String::from(enode));
    }
}

pub fn add_trusted_node(enode: &str) {
    let mut guard = NODE_CONFIG.write();
    if let Some(config) = guard.as_mut() {
        config.discovery.trusted_nodes.push(String::from(enode));
    }
}
