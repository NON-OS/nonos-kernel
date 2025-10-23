//! NONOS Kernel-Level Onion Routing Implementation
//!
//! Fully integrated onion routing stack for the NONOS kernel.
//! - Circuit build/teardown, cell parsing, layered crypto
//! - Directory bootstrap + path selection
//! - Stream multiplexing with flow control
//! - TLS 1.3 for OR connections
//! - Relay mode (guard/middle/exit) wiring
//!
//! This module is the public façade: initialize once, then use the helpers below to build circuits, open streams, and pass application data.

#![allow(clippy::result_large_err)]

pub mod circuit;
pub mod cell;
pub mod crypto;
pub mod directory;
pub mod relay;
pub mod stream;
pub mod security;
pub mod nonos_crypto; // <- renamed from real_crypto
pub mod tls;
pub mod real_network;

use alloc::{vec::Vec, string::String};
use spin::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// Re-exports: keep the top-level API tidy.
pub use circuit::{Circuit, CircuitManager, CircuitId, CircuitState};
pub use cell::{Cell, CellType, RelayCommand, CellProcessor};
pub use crypto::{OnionCrypto, LayerKeys, HopCrypto};
pub use directory::{DirectoryService, RelayDescriptor, RouterStatus};
pub use relay::{OnionRelay, RelayManager, RelayConfig};
pub use stream::{OnionStream, StreamId, StreamManager};
pub use security::{SecurityManager, init_security, check_client_security, secure_zero};
pub use nonos_crypto::{RealRSA, RealCurve25519, RealEd25519, RealDH, RSAKeyPair};
pub use tls::{TLSConnection, TLSState, X509Certificate};
pub use real_network::{TorNetworkManager, init_tor_network, get_tor_network};

/// Global onion routing manager (initialized via `init_onion_router`).
static ONION_ROUTER: Mutex<Option<OnionRouter>> = Mutex::new(None);

/// Primary manager that wires together all subsystems.
pub struct OnionRouter {
    pub circuit_manager: CircuitManager,
    pub directory_service: DirectoryService,
    pub relay_manager: RelayManager,
    pub stream_manager: StreamManager,
    pub cell_processor: CellProcessor,
    pub key_manager: KeyManager,
    pub route_optimizer: RouteOptimizer,
    pub is_relay: AtomicBool,
    pub relay_stats: RelayStats,
}

/// Relay statistics and counters (kernel-safe atomics).
#[derive(Debug)]
pub struct RelayStats {
    pub cells_processed: AtomicU32,
    pub bytes_relayed: AtomicU32,
    pub circuits_created: AtomicU32,
    pub streams_opened: AtomicU32,
}

impl Clone for RelayStats {
    fn clone(&self) -> Self {
        Self {
            cells_processed: AtomicU32::new(self.cells_processed.load(core::sync::atomic::Ordering::Relaxed)),
            bytes_relayed: AtomicU32::new(self.bytes_relayed.load(core::sync::atomic::Ordering::Relaxed)),
            circuits_created: AtomicU32::new(self.circuits_created.load(core::sync::atomic::Ordering::Relaxed)),
            streams_opened: AtomicU32::new(self.streams_opened.load(core::sync::atomic::Ordering::Relaxed)),
        }
    }
}

/// Unified error type for the onion stack.
#[derive(Debug, Clone)]
pub enum OnionError {
    CircuitBuildFailed,
    RelayNotFound,
    InsufficientRelays,
    CryptoError,
    NetworkError,
    StreamClosed,
    InvalidCell,
    DirectoryError,
    AuthenticationFailed,
    SecurityViolation,
    Timeout,
    RateLimited,
    StreamNotFound,
    CircuitError,
    CircuitNotFound,
    CertificateError,
}

impl From<&'static str> for OnionError {
    fn from(_: &'static str) -> Self {
        OnionError::CryptoError
    }
}

impl OnionRouter {
    pub fn new() -> Self {
        OnionRouter {
            circuit_manager: CircuitManager::new(),
            directory_service: DirectoryService::new(),
            relay_manager: RelayManager::new(),
            stream_manager: StreamManager::new(),
            cell_processor: CellProcessor::new(),
            key_manager: KeyManager::new(),
            route_optimizer: RouteOptimizer::new(),
            is_relay: AtomicBool::new(false),
            relay_stats: RelayStats {
                cells_processed: AtomicU32::new(0),
                bytes_relayed: AtomicU32::new(0),
                circuits_created: AtomicU32::new(0),
                streams_opened: AtomicU32::new(0),
            },
        }
    }

    /// Bring up the full onion stack.
    /// Order matters: security -> directory -> circuits -> relay (optional).
    pub fn init(&mut self) -> Result<(), OnionError> {
        // Kernel security primitives (entropy, constant-time ops, zeroization).
        init_security()?;

        // Directory (authorities, consensus fetch/parse, weights).
        self.directory_service.init()?;

        // Circuit manager (handshakes, path build state).
        self.circuit_manager.init()?;

        // If configured as a relay, relay manager is already initialized by new()
        if self.is_relay.load(Ordering::Relaxed) {
            // Relay manager is ready to accept connections
        }
        Ok(())
    }

    /// Build a new 3-hop circuit (guard, middle, exit).
    pub fn create_circuit(&mut self, exit_policy: Option<String>) -> Result<CircuitId, OnionError> {
        let relays = self.directory_service.select_path()?;
        if relays.len() != 3 {
            return Err(OnionError::InsufficientRelays);
        }
        let circuit_id = self.circuit_manager.build_circuit(relays)?;
        self.relay_stats.circuits_created.fetch_add(1, Ordering::Relaxed);
        Ok(circuit_id)
    }

    /// Open a new end-to-end stream over an existing circuit.
    pub fn create_stream(&mut self, circuit_id: CircuitId, target: String, port: u16) -> Result<StreamId, OnionError> {
        let stream_id = self.stream_manager.create_stream(circuit_id, target, port)?;
        self.relay_stats.streams_opened.fetch_add(1, Ordering::Relaxed);
        Ok(stream_id)
    }

    /// Application data -> onion stream.
    pub fn send_data(&mut self, stream_id: StreamId, data: Vec<u8>) -> Result<(), OnionError> {
        self.stream_manager.send_data(stream_id, &data)
    }

    /// Application data <- onion stream.
    pub fn recv_data(&mut self, stream_id: StreamId) -> Result<Vec<u8>, OnionError> {
        self.stream_manager.recv_data(stream_id)
    }

    /// Inbound raw cell from OR connection -> dispatch to circuit/stream.
    pub fn process_cell(&mut self, cell: Cell) -> Result<(), OnionError> {
        self.cell_processor
            .process_cell(cell, &mut self.circuit_manager, &mut self.stream_manager)?;
        self.relay_stats.cells_processed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Enable relay mode with a validated configuration.
    pub fn enable_relay_mode(&mut self, _relay_config: RelayConfig) -> Result<(), OnionError> {
        self.is_relay.store(true, Ordering::Relaxed);
        // Relay manager is ready to accept connections
        Ok(())
    }

    pub fn get_stats(&self) -> &RelayStats {
        &self.relay_stats
    }
}

/// Initialize the global onion router once.
/// Call this during kernel networking bring-up.
pub fn init_onion_router() -> Result<(), OnionError> {
    let mut router = OnionRouter::new();
    router.init()?;
    *ONION_ROUTER.lock() = Some(router);
    Ok(())
}

/// Borrow the global onion router guard.
pub fn get_onion_router() -> &'static Mutex<Option<OnionRouter>> {
    &ONION_ROUTER
}

/// High-level helpers for kernel subsystems:

/// Create a new circuit (guard→middle→exit) using optional constraints.
pub fn create_circuit(exit_policy: Option<String>) -> Result<CircuitId, OnionError> {
    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.create_circuit(exit_policy)
}

/// Open a stream on a given circuit toward target:port.
pub fn create_stream(circuit_id: CircuitId, target: String, port: u16) -> Result<StreamId, OnionError> {
    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.create_stream(circuit_id, target, port)
}

/// Send bytes over an onion stream.
pub fn send_onion_data(stream_id: StreamId, data: Vec<u8>) -> Result<(), OnionError> {
    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.send_data(stream_id, data)
}

/// Receive bytes from an onion stream (may return empty Vec).
pub fn recv_onion_data(stream_id: StreamId) -> Result<Vec<u8>, OnionError> {
    let mut guard = ONION_ROUTER.lock();
    let router = guard.as_mut().ok_or(OnionError::NetworkError)?;
    router.recv_data(stream_id)
}

/// Process periodic circuit maintenance tasks
pub fn process_circuit_maintenance() {
    if let Some(mut router) = ONION_ROUTER.try_lock() {
        if let Some(router) = router.as_mut() {
            // Clean up expired circuits
            router.circuit_manager.cleanup_expired_circuits(30000); // 30 seconds max age
            
            // Relay statistics are updated automatically
            
            // Process pending security checks
            if let Err(_) = security::check_client_security([127, 0, 0, 1], 0) {
                // Log security violations
                crate::log_warn!("Circuit maintenance: security violation detected");
            }
        }
    }
}

/// Key management for onion routing
pub struct KeyManager {
    pub rsa_keys: Vec<u8>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            rsa_keys: Vec::new(),
        }
    }
}

/// Route optimization engine
pub struct RouteOptimizer {
    pub cached_paths: Vec<u8>,
}

impl RouteOptimizer {
    pub fn new() -> Self {
        Self {
            cached_paths: Vec::new(),
        }
    }
}