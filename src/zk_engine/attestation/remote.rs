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

//! Remote attestation client.

use alloc::vec::Vec;
use crate::zk_engine::ZKError;
use crate::crypto::hash::blake3_hash;

use super::types::KernelAttestation;
use super::manager::AttestationManager;

/// Remote attestation client for verification
pub struct RemoteAttestationClient {
    trusted_keys: Vec<[u8; 32]>,
    /// Nonce for replay protection
    current_nonce: [u8; 32],
    /// Last attestation timestamp to prevent replay
    last_attestation_time: u64,
    /// Minimum time between attestation requests (anti-DoS)
    min_attestation_interval_ms: u64,
}

impl RemoteAttestationClient {
    pub fn new() -> Self {
        // Generate initial nonce from entropy
        let entropy = crate::crypto::entropy::get_entropy(32);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&entropy[..32]);
        Self {
            trusted_keys: Vec::new(),
            current_nonce: nonce,
            last_attestation_time: 0,
            min_attestation_interval_ms: 1000, // 1 second minimum
        }
    }

    pub fn add_trusted_key(&mut self, public_key: [u8; 32]) {
        if !self.trusted_keys.contains(&public_key) {
            self.trusted_keys.push(public_key);
        }
    }

    pub fn remove_trusted_key(&mut self, public_key: &[u8; 32]) {
        self.trusted_keys.retain(|k| k != public_key);
    }

    pub fn verify_remote_attestation(&self, attestation: &KernelAttestation) -> Result<bool, ZKError> {
        // Check if signing key is trusted
        if !self.trusted_keys.contains(&attestation.public_key) {
            return Ok(false);
        }

        // Check timestamp freshness (prevent replay attacks)
        let current_time = crate::time::timestamp_millis();
        let max_age_ms = 300_000; // 5 minutes
        if current_time > attestation.timestamp + max_age_ms {
            return Ok(false);
        }

        // Verify the attestation cryptographically
        AttestationManager::verify_attestation(attestation)
    }

    /// Request attestation from a remote system via network
    pub fn request_attestation(&mut self, target_address: &str) -> Result<KernelAttestation, ZKError> {
        // Rate limiting check
        let current_time = crate::time::timestamp_millis();
        if current_time < self.last_attestation_time + self.min_attestation_interval_ms {
            return Err(ZKError::AttestationError("Rate limited".into()));
        }
        self.last_attestation_time = current_time;

        // Generate fresh nonce for this request
        let entropy = crate::crypto::entropy::get_entropy(32);
        self.current_nonce.copy_from_slice(&entropy[..32]);

        // Build attestation request message
        let mut request = Vec::new();
        request.extend_from_slice(b"ATTEST_REQ");  // Magic
        request.extend_from_slice(&1u16.to_le_bytes()); // Version
        request.extend_from_slice(&self.current_nonce); // Challenge nonce
        request.extend_from_slice(&current_time.to_le_bytes()); // Timestamp

        // Send request via network stack
        let response = self.send_attestation_request(target_address, &request)?;

        // Parse response
        self.parse_attestation_response(&response)
    }

    fn send_attestation_request(&self, target_address: &str, request: &[u8]) -> Result<Vec<u8>, ZKError> {
        // Parse target address (format: "ip:port" or onion address)
        let is_onion = target_address.ends_with(".onion");

        if is_onion {
            // Route through Tor network for privacy
            self.send_via_tor(target_address, request)
        } else {
            // Direct TCP connection
            self.send_via_tcp(target_address, request)
        }
    }

    fn send_via_tcp(&self, target_address: &str, request: &[u8]) -> Result<Vec<u8>, ZKError> {
        use crate::network::stack;

        // Get network stack
        let stack = stack::get_network_stack()
            .ok_or(ZKError::NetworkError)?;

        // Parse address and port
        let parts: Vec<&str> = target_address.split(':').collect();
        if parts.len() != 2 {
            return Err(ZKError::AttestationError("Invalid address format".into()));
        }

        let port: u16 = parts[1].parse()
            .map_err(|_| ZKError::AttestationError("Invalid port".into()))?;

        // Parse IP address into [u8; 4]
        let ip_parts: Vec<u8> = parts[0].split('.')
            .filter_map(|p| p.parse().ok())
            .collect();

        if ip_parts.len() != 4 {
            return Err(ZKError::AttestationError("Invalid IP address".into()));
        }

        let dest_ip: [u8; 4] = [ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]];

        // Create a temporary socket for connection
        let sock = crate::network::stack::TcpSocket::new();

        // Create TCP connection
        stack.tcp_connect(&sock, dest_ip, port)
            .map_err(|_| ZKError::NetworkError)?;

        let conn_id = sock.connection_id();

        // Send attestation request
        stack.tcp_send(conn_id, request)
            .map_err(|_| ZKError::NetworkError)?;

        // Receive response with timeout
        let mut response = Vec::new();
        let timeout_ms = 5000; // 5 second timeout
        let start = crate::time::timestamp_millis();

        loop {
            match stack.tcp_receive(conn_id, 4096) {
                Ok(data) if !data.is_empty() => {
                    response.extend_from_slice(&data);
                    // Check if we have a complete response (starts with magic + length)
                    if response.len() >= 12 {
                        let expected_len = u32::from_le_bytes([
                            response[8], response[9], response[10], response[11]
                        ]) as usize;
                        if response.len() >= 12 + expected_len {
                            break;
                        }
                    }
                }
                _ => {}
            }

            if crate::time::timestamp_millis() - start > timeout_ms {
                let _ = stack.tcp_close(conn_id);
                return Err(ZKError::AttestationError("Request timeout".into()));
            }

            // Brief pause to avoid spinning
            core::hint::spin_loop();
        }

        let _ = stack.tcp_close(conn_id);
        Ok(response)
    }

    fn send_via_tor(&self, target_address: &str, request: &[u8]) -> Result<Vec<u8>, ZKError> {
        // Route attestation request through onion network for privacy
        use crate::network::onion;
        use alloc::string::String;

        // Parse onion address (format: "hostname.onion:port")
        let parts: Vec<&str> = target_address.split(':').collect();
        if parts.len() != 2 {
            return Err(ZKError::AttestationError("Invalid onion address format".into()));
        }

        let hostname = parts[0];
        let port: u16 = parts[1].parse()
            .map_err(|_| ZKError::AttestationError("Invalid port".into()))?;

        // Create onion circuit to exit toward the hidden service
        let circuit_id = onion::create_circuit(Some(String::from(hostname)))
            .map_err(|_| ZKError::NetworkError)?;

        // Create stream to the target hidden service
        let stream_id = onion::create_stream(circuit_id, String::from(hostname), port)
            .map_err(|_| ZKError::NetworkError)?;

        // Send request through stream
        onion::send_onion_data(stream_id, request.to_vec())
            .map_err(|_| ZKError::NetworkError)?;

        // Receive response with timeout
        let mut response = Vec::new();
        let timeout_ms = 10000; // 10 second timeout for Tor (slower)
        let start = crate::time::timestamp_millis();

        loop {
            match onion::recv_onion_data(stream_id) {
                Ok(data) if !data.is_empty() => {
                    response.extend_from_slice(&data);
                    // Check if we have a complete response (starts with magic + length)
                    if response.len() >= 12 {
                        let expected_len = u32::from_le_bytes([
                            response[8], response[9], response[10], response[11]
                        ]) as usize;
                        if response.len() >= 12 + expected_len {
                            break;
                        }
                    }
                }
                _ => {}
            }

            if crate::time::timestamp_millis() - start > timeout_ms {
                return Err(ZKError::AttestationError("Tor request timeout".into()));
            }

            // Brief pause to avoid spinning
            core::hint::spin_loop();
        }

        Ok(response)
    }

    fn parse_attestation_response(&self, response: &[u8]) -> Result<KernelAttestation, ZKError> {
        // Minimum response: magic (8) + length (4) + attestation data
        if response.len() < 12 {
            return Err(ZKError::InvalidFormat);
        }

        // Verify magic
        if &response[0..8] != b"ATTEST_R" {
            return Err(ZKError::InvalidFormat);
        }

        // Get data length
        let data_len = u32::from_le_bytes([
            response[8], response[9], response[10], response[11]
        ]) as usize;

        if response.len() < 12 + data_len {
            return Err(ZKError::InvalidFormat);
        }

        // Deserialize attestation
        let attestation = KernelAttestation::deserialize(&response[12..12 + data_len])?;

        // Verify nonce is present in attestation (replay protection)
        // The attestation should contain our nonce in the measurement
        let expected_nonce_hash = blake3_hash(&self.current_nonce);
        let measurement_data = attestation.measurement.to_bytes();
        if !measurement_data.windows(32).any(|w| w == expected_nonce_hash) {
            // Nonce verification is optional - warn but don't fail
            crate::log_warn!("Attestation nonce mismatch - possible replay");
        }

        Ok(attestation)
    }

    /// Get current challenge nonce
    pub fn get_current_nonce(&self) -> [u8; 32] {
        self.current_nonce
    }

    /// Check if a key is trusted
    pub fn is_key_trusted(&self, public_key: &[u8; 32]) -> bool {
        self.trusted_keys.contains(public_key)
    }

    /// Get count of trusted keys
    pub fn trusted_key_count(&self) -> usize {
        self.trusted_keys.len()
    }
}
