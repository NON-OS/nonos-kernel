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

//! SOCKS5 Proxy Server

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::network::onion::{create_circuit, CircuitId};

use super::protocol::{Socks5Error, SOCKS5_DEFAULT_PORT};

/// SOCKS5 proxy server
struct Socks5Server {
    /// Listening port
    port: u16,
    /// Server running flag
    running: AtomicBool,
    /// Circuit pool (pre-built circuits for faster connections)
    circuit_pool: Mutex<Vec<CircuitId>>,
}

impl Socks5Server {
    /// Create new SOCKS5 server
    fn new() -> Self {
        Self {
            port: SOCKS5_DEFAULT_PORT,
            running: AtomicBool::new(false),
            circuit_pool: Mutex::new(Vec::with_capacity(8)),
        }
    }

    /// Start the server
    fn start(&self) -> Result<(), Socks5Error> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already running
        }

        crate::log::info!("SOCKS5: Starting proxy server on port {}", self.port);

        // Pre-build some circuits for faster initial connections
        self.refill_circuit_pool();

        Ok(())
    }

    /// Stop the server
    fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return; // Already stopped
        }

        crate::log::info!("SOCKS5: Stopping proxy server");

        // Clear circuit pool
        self.circuit_pool.lock().clear();
    }

    /// Refill the circuit pool
    fn refill_circuit_pool(&self) {
        let mut pool = self.circuit_pool.lock();
        let target_size = 4; // Keep 4 pre-built circuits

        while pool.len() < target_size {
            match create_circuit(None) {
                Ok(circuit_id) => {
                    pool.push(circuit_id);
                }
                Err(e) => {
                    crate::log_warn!("SOCKS5: Failed to pre-build circuit: {:?}", e);
                    break;
                }
            }
        }
    }
}

// =============================================================================
// Global server instance and API
// =============================================================================

static SOCKS_SERVER: Mutex<Option<Socks5Server>> = Mutex::new(None);

/// Start the global SOCKS5 server
pub(crate) fn start_socks_server() -> Result<(), Socks5Error> {
    let mut guard = SOCKS_SERVER.lock();

    if guard.is_some() {
        return Ok(()); // Already started
    }

    let server = Socks5Server::new();
    server.start()?;
    *guard = Some(server);

    crate::log::info!("SOCKS5: Server started on port {}", SOCKS5_DEFAULT_PORT);
    Ok(())
}

/// Stop the global SOCKS5 server
pub(crate) fn stop_socks_server() {
    let mut guard = SOCKS_SERVER.lock();
    if let Some(server) = guard.take() {
        server.stop();
    }
}
