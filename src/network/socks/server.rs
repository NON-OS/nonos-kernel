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
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::network::onion::{create_circuit, CircuitId};

use super::protocol::{Socks5Error, SOCKS5_DEFAULT_PORT};

struct Socks5Server {
    port: u16,
    running: AtomicBool,
    circuit_pool: Mutex<Vec<CircuitId>>,
}

impl Socks5Server {
    fn new() -> Self {
        Self {
            port: SOCKS5_DEFAULT_PORT,
            running: AtomicBool::new(false),
            circuit_pool: Mutex::new(Vec::with_capacity(8)),
        }
    }

    fn start(&self) -> Result<(), Socks5Error> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        crate::log::info!("SOCKS5: Starting proxy server on port {}", self.port);

        self.refill_circuit_pool();

        Ok(())
    }

    fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }

        crate::log::info!("SOCKS5: Stopping proxy server");

        self.circuit_pool.lock().clear();
    }

    fn refill_circuit_pool(&self) {
        let mut pool = self.circuit_pool.lock();
        let target_size = 4;

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


static SOCKS_SERVER: Mutex<Option<Socks5Server>> = Mutex::new(None);

pub(crate) fn start_socks_server() -> Result<(), Socks5Error> {
    let mut guard = SOCKS_SERVER.lock();

    if guard.is_some() {
        return Ok(());
    }

    let server = Socks5Server::new();
    server.start()?;
    *guard = Some(server);

    crate::log::info!("SOCKS5: Server started on port {}", SOCKS5_DEFAULT_PORT);
    Ok(())
}

pub(crate) fn stop_socks_server() {
    let mut guard = SOCKS_SERVER.lock();
    if let Some(server) = guard.take() {
        server.stop();
    }
}

