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

use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::network::onion::{
    create_circuit, create_stream, recv_onion_data, send_onion_data, CircuitId, OnionError,
};
use super::interceptor_types::{
    InterceptorConfig, InterceptorStats, TransparentConnection, ip_in_subnet, is_local_network,
};

pub(crate) use super::interceptor_types::InterceptorConfig as Config;

pub(crate) struct TransparentInterceptor {
    config: InterceptorConfig,
    running: AtomicBool,
    connections: Mutex<BTreeMap<u16, TransparentConnection>>,
    circuit_pool: Mutex<Vec<CircuitId>>,
    stats: InterceptorStats,
}

impl TransparentInterceptor {
    pub(super) fn new() -> Self {
        Self {
            config: InterceptorConfig::default(),
            running: AtomicBool::new(false),
            connections: Mutex::new(BTreeMap::new()),
            circuit_pool: Mutex::new(Vec::new()),
            stats: InterceptorStats::default(),
        }
    }

    pub(super) fn with_config(config: InterceptorConfig) -> Self {
        Self {
            config,
            running: AtomicBool::new(false),
            connections: Mutex::new(BTreeMap::new()),
            circuit_pool: Mutex::new(Vec::new()),
            stats: InterceptorStats::default(),
        }
    }

    pub(super) fn start(&self) -> Result<(), &'static str> {
        if !self.config.enabled {
            return Err("Interceptor is disabled in config");
        }

        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        crate::log::info!("Transparent: Starting traffic interceptor");
        self.refill_circuits();
        Ok(())
    }

    pub(super) fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }

        crate::log::info!("Transparent: Stopping traffic interceptor");
        self.connections.lock().clear();
        self.circuit_pool.lock().clear();
    }

    pub(super) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub(super) fn should_intercept(&self, dest_ip: [u8; 4], dest_port: u16, protocol: u8) -> bool {
        if !self.is_running() {
            return false;
        }

        if protocol != 6 && self.config.intercept_tcp {
            if protocol != 17 || !self.config.intercept_dns || dest_port != 53 {
                return false;
            }
        }

        if self.config.bypass_ips.contains(&dest_ip) {
            return false;
        }

        for (range_ip, prefix) in &self.config.bypass_ranges {
            if ip_in_subnet(dest_ip, *range_ip, *prefix) {
                return false;
            }
        }

        if self.config.bypass_local && is_local_network(dest_ip) {
            return false;
        }

        if self.config.blocked_ports.contains(&dest_port) {
            return false;
        }

        if !self.config.allowed_ports.is_empty() && !self.config.allowed_ports.contains(&dest_port) {
            return false;
        }

        true
    }

    pub(super) fn intercept_connection(
        &self,
        local_port: u16,
        dest_ip: [u8; 4],
        dest_port: u16,
    ) -> Result<(), OnionError> {
        if !self.is_running() {
            return Err(OnionError::NetworkError);
        }

        self.stats.packets_intercepted.fetch_add(1, Ordering::Relaxed);

        let circuit_id = self.get_circuit()?;

        let dest_str = alloc::format!("{}.{}.{}.{}", dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]);
        let stream_id = create_stream(circuit_id, dest_str.clone(), dest_port)?;

        let now = crate::arch::x86_64::time::tsc::elapsed_us();

        let mut connections = self.connections.lock();
        connections.insert(
            local_port,
            TransparentConnection {
                stream_id,
                bytes_sent: 0,
                bytes_received: 0,
                last_activity: now,
            },
        );

        self.stats.connections_established.fetch_add(1, Ordering::Relaxed);

        crate::log::info!(
            "Transparent: Intercepted connection to {}:{} on local port {}",
            dest_str,
            dest_port,
            local_port
        );

        Ok(())
    }

    pub(super) fn send_data(&self, local_port: u16, data: &[u8]) -> Result<(), OnionError> {
        let stream_id = {
            let mut connections = self.connections.lock();
            let conn = connections.get_mut(&local_port).ok_or(OnionError::CircuitClosed)?;
            conn.bytes_sent += data.len() as u64;
            conn.last_activity = crate::arch::x86_64::time::tsc::elapsed_us();
            conn.stream_id
        };

        send_onion_data(stream_id, data.to_vec())?;
        self.stats.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    pub(super) fn recv_data(&self, local_port: u16) -> Result<Vec<u8>, OnionError> {
        let stream_id = {
            let connections = self.connections.lock();
            let conn = connections.get(&local_port).ok_or(OnionError::CircuitClosed)?;
            conn.stream_id
        };

        let data = recv_onion_data(stream_id)?;

        if !data.is_empty() {
            let mut connections = self.connections.lock();
            if let Some(conn) = connections.get_mut(&local_port) {
                conn.bytes_received += data.len() as u64;
                conn.last_activity = crate::arch::x86_64::time::tsc::elapsed_us();
            }
            self.stats.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
        }

        Ok(data)
    }

    pub(super) fn close_connection(&self, local_port: u16) {
        let mut connections = self.connections.lock();
        if let Some(_conn) = connections.remove(&local_port) {
            crate::log::info!("Transparent: Closed intercepted connection on port {}", local_port);
        }
    }

    pub(super) fn intercept_dns(&self, query: &[u8]) -> Result<Vec<u8>, OnionError> {
        if !self.config.intercept_dns {
            return Err(OnionError::NetworkError);
        }

        self.stats.dns_queries_intercepted.fetch_add(1, Ordering::Relaxed);

        let circuit_id = self.get_circuit()?;
        let stream_id = create_stream(circuit_id, "dns.resolver".to_string(), 53)?;

        send_onion_data(stream_id, query.to_vec())?;
        let response = recv_onion_data(stream_id)?;

        Ok(response)
    }

    pub(super) fn cleanup(&self) {
        let now = crate::arch::x86_64::time::tsc::elapsed_us();
        let idle_timeout = 120_000_000;

        let mut to_remove = Vec::new();
        {
            let connections = self.connections.lock();
            for (&port, conn) in connections.iter() {
                if now.saturating_sub(conn.last_activity) > idle_timeout {
                    to_remove.push(port);
                }
            }
        }

        for port in to_remove {
            self.close_connection(port);
        }

        self.refill_circuits();
    }

    fn get_circuit(&self) -> Result<CircuitId, OnionError> {
        if let Some(circuit_id) = self.circuit_pool.lock().pop() {
            return Ok(circuit_id);
        }

        create_circuit(None).map_err(|e| {
            self.stats.connections_failed.fetch_add(1, Ordering::Relaxed);
            e
        })
    }

    fn refill_circuits(&self) {
        let mut pool = self.circuit_pool.lock();
        let target_size = 4;

        while pool.len() < target_size {
            match create_circuit(None) {
                Ok(circuit_id) => pool.push(circuit_id),
                Err(_) => break,
            }
        }
    }
}

impl Default for TransparentInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

static INTERCEPTOR: Mutex<Option<TransparentInterceptor>> = Mutex::new(None);

pub(crate) fn init_interceptor(config: InterceptorConfig) -> Result<(), &'static str> {
    let mut guard = INTERCEPTOR.lock();

    if guard.is_some() {
        return Err("Interceptor already initialized");
    }

    let interceptor = TransparentInterceptor::with_config(config);
    interceptor.start()?;
    *guard = Some(interceptor);

    crate::log::info!("Transparent: Interceptor initialized");
    Ok(())
}

pub(crate) fn get_interceptor() -> &'static Mutex<Option<TransparentInterceptor>> {
    &INTERCEPTOR
}
