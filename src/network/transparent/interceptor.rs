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

//! Transparent Traffic Interceptor
//!
//! Intercepts outbound packets and redirects them through the onion network.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::network::onion::{create_circuit, CircuitId};

/// Configuration for the transparent interceptor
#[derive(Debug, Clone)]
pub(crate) struct InterceptorConfig {
    pub(crate) enabled: bool,
    pub(crate) intercept_tcp: bool,
    pub(crate) intercept_dns: bool,
    pub(crate) bypass_local: bool,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            intercept_tcp: true,
            intercept_dns: true,
            bypass_local: true,
        }
    }
}

/// Transparent traffic interceptor
pub(crate) struct TransparentInterceptor {
    config: InterceptorConfig,
    running: AtomicBool,
    circuit_pool: Mutex<Vec<CircuitId>>,
}

impl TransparentInterceptor {
    fn with_config(config: InterceptorConfig) -> Self {
        Self {
            config,
            running: AtomicBool::new(false),
            circuit_pool: Mutex::new(Vec::new()),
        }
    }

    fn start(&self) -> Result<(), &'static str> {
        if !self.config.enabled {
            return Err("Interceptor is disabled in config");
        }

        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        crate::log::info!(
            "Transparent: Starting interceptor (tcp={}, dns={}, bypass_local={})",
            self.config.intercept_tcp,
            self.config.intercept_dns,
            self.config.bypass_local
        );
        self.refill_circuits();

        Ok(())
    }

    pub(super) fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }

        crate::log::info!("Transparent: Stopping traffic interceptor");
        self.circuit_pool.lock().clear();
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
        Self::with_config(InterceptorConfig::default())
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
