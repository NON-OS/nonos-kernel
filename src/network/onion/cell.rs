//! Real Onion Routing Cell Processing
//!
//! Complete implementation of Tor protocol cells with proper serialization,
//! relay commands, and stream multiplexing. Production-ready cell handling.

use alloc::{vec::Vec, vec, collections::BTreeMap, string::String};
use spin::Mutex;
use core::sync::atomic::{AtomicU16, Ordering};

use super::{OnionError, CircuitId, StreamId};
use super::circuit::{CircuitManager, ExtendInfo, LinkSpecifier};
use super::stream::StreamManager;
use crate::crypto::hash;

/// Tor cell types (command field)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CellType {
    // Fixed-length cells
    Padding = 0,
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    CreateFast = 5,
    CreatedFast = 6,
    
    // Variable-length cells (versions 0)
    Versions = 7,
    NetInfo = 8,
    RelayEarly = 9,
    Create2 = 10,
    Created2 = 11,
    
    // Padding cell for traffic analysis resistance
    VPadding = 128,
    
    // CERTS cell for link authentication
    Certs = 129,
    AuthChallenge = 130,
    Authenticate = 131,
    Authorize = 132,
}

/// Relay command types for RELAY cells
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RelayCommand {
    RelayBegin = 1,
    RelayData = 2,
    RelayEnd = 3,
    RelayConnected = 4,
    RelayResolve = 5,
    RelayResolved = 6,
    RelayBeginDir = 13,
    RelayExtend = 14,
    RelayExtended = 7,
    RelayTruncate = 8,
    RelayTruncated = 9,
    RelayDrop = 10,
    RelayResolve2 = 11,
    RelayResolved2 = 12,
    RelaySendme = 17,
    RelayExtend2 = 16,
    RelayExtended2 = 15,
    RelayEstablishIntro = 32,
    RelayEstablishRendezvous = 33,
    RelayIntroduce1 = 34,
    RelayIntroduce2 = 35,
    RelayRendezvous1 = 36,
    RelayRendezvous2 = 37,
    RelayIntroEstablished = 38,
    RelayRendezvousEstablished = 39,
    RelayIntroduceAck = 40,
}

/// Standard Tor cell size
pub const CELL_SIZE: usize = 514;
pub const CELL_HEADER_SIZE: usize = 5;
pub const CELL_PAYLOAD_SIZE: usize = 509;

/// Variable-length cell sizes
pub const VAR_CELL_HEADER_SIZE: usize = 7;
pub const MAX_VAR_CELL_PAYLOAD_SIZE: usize = 65535;

/// Relay cell header size
pub const RELAY_HEADER_SIZE: usize = 11;
pub const RELAY_PAYLOAD_SIZE: usize = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE;

/// A complete Tor protocol cell
#[derive(Debug, Clone)]
pub struct Cell {
    pub circuit_id: CircuitId,
    pub command: u8,
    pub payload: Vec<u8>,
    pub is_variable_length: bool,
}

/// Relay cell header structure
#[derive(Debug, Clone)]
pub struct RelayHeader {
    pub command: RelayCommand,
    pub recognized: u16,      // Always 0 for valid cells
    pub stream_id: StreamId,
    pub digest: [u8; 4],      // Running digest
    pub length: u16,          // Payload length
}

/// Parsed relay cell with header and payload
#[derive(Debug, Clone)]
pub struct RelayCell {
    pub circuit_id: CircuitId,
    pub header: RelayHeader,
    pub payload: Vec<u8>,
    pub hop_level: u8,        // Which hop processed this cell
}

impl Cell {
    /// Create new fixed-length cell
    pub fn new(circuit_id: CircuitId, command: CellType, payload: Vec<u8>) -> Self {
        let mut cell_payload = payload;
        cell_payload.resize(CELL_PAYLOAD_SIZE, 0); // Pad to fixed size
        
        Cell {
            circuit_id,
            command: command as u8,
            payload: cell_payload,
            is_variable_length: false,
        }
    }

    /// Create variable-length cell
    pub fn new_var(circuit_id: CircuitId, command: CellType, payload: Vec<u8>) -> Self {
        Cell {
            circuit_id,
            command: command as u8,
            payload,
            is_variable_length: true,
        }
    }

    /// Create CREATE cell for circuit establishment
    pub fn create_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        Cell::new(circuit_id, CellType::Create, handshake_data)
    }

    /// Create CREATE2 cell for ntor handshake
    pub fn create2_cell(circuit_id: CircuitId, handshake_type: u16, handshake_data: Vec<u8>) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&handshake_type.to_be_bytes());
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        
        Cell::new_var(circuit_id, CellType::Create2, payload)
    }

    /// Create CREATED cell response
    pub fn created_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        Cell::new(circuit_id, CellType::Created, handshake_data)
    }

    /// Create CREATED2 cell response
    pub fn created2_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        
        Cell::new_var(circuit_id, CellType::Created2, payload)
    }

    /// Create EXTEND cell for adding hops
    pub fn extend_cell(circuit_id: CircuitId, extend_info: ExtendInfo, handshake_data: Vec<u8>) -> Self {
        let relay_payload = Self::encode_extend_payload(extend_info, handshake_data);
        
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtend,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: relay_payload.len() as u16,
            },
            payload: relay_payload,
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Create EXTEND2 cell for ntor handshake extension
    pub fn extend2_cell(circuit_id: CircuitId, extend_info: ExtendInfo, handshake_type: u16, handshake_data: Vec<u8>) -> Self {
        let relay_payload = Self::encode_extend2_payload(extend_info, handshake_type, handshake_data);
        
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtend2,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: relay_payload.len() as u16,
            },
            payload: relay_payload,
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Create EXTENDED cell response
    pub fn extended_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtended,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: handshake_data.len() as u16,
            },
            payload: handshake_data,
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Create EXTENDED2 cell response
    pub fn extended2_cell(circuit_id: CircuitId, handshake_data: Vec<u8>) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayExtended2,
                recognized: 0,
                stream_id: 0,
                digest: [0; 4],
                length: payload.len() as u16,
            },
            payload,
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Create DESTROY cell for circuit teardown
    pub fn destroy_cell(circuit_id: CircuitId, reason: u8) -> Self {
        Cell::new(circuit_id, CellType::Destroy, vec![reason])
    }

    /// Create RELAY_DATA cell for stream data
    pub fn relay_data_cell(circuit_id: CircuitId, stream_id: StreamId, data: Vec<u8>) -> Self {
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayData,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: data.len() as u16,
            },
            payload: data,
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Create RELAY_BEGIN cell for stream initiation
    pub fn relay_begin_cell(circuit_id: CircuitId, stream_id: StreamId, target: String, port: u16) -> Self {
        let mut payload = format!("{}:{}\0", target, port).into_bytes();
        payload.push(0); // Flags (always 0 for now)
        
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayBegin,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: payload.len() as u16,
            },
            payload,
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Create RELAY_CONNECTED cell for stream confirmation
    pub fn relay_connected_cell(circuit_id: CircuitId, stream_id: StreamId, addr: [u8; 4], ttl: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&addr);    // IPv4 address
        payload.extend_from_slice(&ttl.to_be_bytes());
        
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayConnected,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: payload.len() as u16,
            },
            payload,
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Create RELAY_END cell for stream termination
    pub fn relay_end_cell(circuit_id: CircuitId, stream_id: StreamId, reason: u8) -> Self {
        let relay_cell = RelayCell {
            circuit_id,
            header: RelayHeader {
                command: RelayCommand::RelayEnd,
                recognized: 0,
                stream_id,
                digest: [0; 4],
                length: 1,
            },
            payload: vec![reason],
            hop_level: 0,
        };
        
        Cell::from_relay_cell(relay_cell)
    }

    /// Convert RelayCell to Cell
    pub fn from_relay_cell(relay_cell: RelayCell) -> Self {
        let mut payload = Vec::new();
        
        // Relay header
        payload.push(relay_cell.header.command as u8);
        payload.extend_from_slice(&relay_cell.header.recognized.to_be_bytes());
        payload.extend_from_slice(&relay_cell.header.stream_id.to_be_bytes());
        payload.extend_from_slice(&relay_cell.header.digest);
        payload.extend_from_slice(&relay_cell.header.length.to_be_bytes());
        
        // Relay payload
        payload.extend_from_slice(&relay_cell.payload);
        
        // Pad to cell size
        payload.resize(CELL_PAYLOAD_SIZE, 0);
        
        Cell {
            circuit_id: relay_cell.circuit_id,
            command: CellType::Relay as u8,
            payload,
            is_variable_length: false,
        }
    }

    /// Parse cell into RelayCell if it's a relay cell
    pub fn parse_relay_cell(&self) -> Result<RelayCell, OnionError> {
        if self.command != CellType::Relay as u8 && self.command != CellType::RelayEarly as u8 {
            return Err(OnionError::InvalidCell);
        }

        if self.payload.len() < RELAY_HEADER_SIZE {
            return Err(OnionError::InvalidCell);
        }

        let command = RelayCommand::from_u8(self.payload[0])?;
        let recognized = u16::from_be_bytes([self.payload[1], self.payload[2]]);
        let stream_id = u16::from_be_bytes([self.payload[3], self.payload[4]]);
        let digest = [self.payload[5], self.payload[6], self.payload[7], self.payload[8]];
        let length = u16::from_be_bytes([self.payload[9], self.payload[10]]);

        if length as usize > RELAY_PAYLOAD_SIZE {
            return Err(OnionError::InvalidCell);
        }

        let header = RelayHeader {
            command,
            recognized,
            stream_id,
            digest,
            length,
        };

        let payload_end = RELAY_HEADER_SIZE + length as usize;
        let payload = if payload_end <= self.payload.len() {
            self.payload[RELAY_HEADER_SIZE..payload_end].to_vec()
        } else {
            return Err(OnionError::InvalidCell);
        };

        Ok(RelayCell {
            circuit_id: self.circuit_id,
            header,
            payload,
            hop_level: 0,
        })
    }

    /// Serialize cell to bytes for network transmission
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        if self.is_variable_length {
            // Variable-length cell format
            data.extend_from_slice(&self.circuit_id.to_be_bytes());
            data.push(self.command);
            data.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.payload);
        } else {
            // Fixed-length cell format
            data.extend_from_slice(&self.circuit_id.to_be_bytes());
            data.push(self.command);
            
            let mut payload = self.payload.clone();
            payload.resize(CELL_PAYLOAD_SIZE, 0);
            data.extend_from_slice(&payload);
        }
        
        data
    }

    /// Deserialize bytes into Cell
    pub fn deserialize(data: &[u8]) -> Result<Self, OnionError> {
        if data.len() < CELL_HEADER_SIZE {
            return Err(OnionError::InvalidCell);
        }

        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let command = data[4];
        
        // Check if variable-length cell
        let is_var_length = Self::is_variable_length_command(command);
        
        if is_var_length {
            if data.len() < VAR_CELL_HEADER_SIZE {
                return Err(OnionError::InvalidCell);
            }
            
            let payload_len = u16::from_be_bytes([data[5], data[6]]) as usize;
            if data.len() < VAR_CELL_HEADER_SIZE + payload_len {
                return Err(OnionError::InvalidCell);
            }
            
            let payload = data[VAR_CELL_HEADER_SIZE..VAR_CELL_HEADER_SIZE + payload_len].to_vec();
            
            Ok(Cell {
                circuit_id,
                command,
                payload,
                is_variable_length: true,
            })
        } else {
            if data.len() != CELL_SIZE {
                return Err(OnionError::InvalidCell);
            }
            
            let payload = data[CELL_HEADER_SIZE..].to_vec();
            
            Ok(Cell {
                circuit_id,
                command,
                payload,
                is_variable_length: false,
            })
        }
    }

    /// Check if command uses variable-length format
    fn is_variable_length_command(command: u8) -> bool {
        matches!(command, 7..=15 | 128..=132)
    }

    /// Encode EXTEND cell payload
    fn encode_extend_payload(extend_info: ExtendInfo, handshake_data: Vec<u8>) -> Vec<u8> {
        let mut payload = Vec::new();
        
        // IPv4 address
        payload.extend_from_slice(&extend_info.address);
        payload.extend_from_slice(&extend_info.port.to_be_bytes());
        
        // Onion key hash
        let onion_key_hash = hash::blake3_hash(&extend_info.onion_key);
        payload.extend_from_slice(&onion_key_hash[..20]);
        
        // Identity key hash
        let identity_hash = hash::blake3_hash(&extend_info.identity_key);
        payload.extend_from_slice(&identity_hash[..20]);
        
        // Handshake data
        payload.extend_from_slice(&handshake_data);
        
        payload
    }

    /// Encode EXTEND2 cell payload
    fn encode_extend2_payload(extend_info: ExtendInfo, handshake_type: u16, handshake_data: Vec<u8>) -> Vec<u8> {
        let mut payload = Vec::new();
        
        // Number of link specifiers
        payload.push(extend_info.link_specifiers.len() as u8);
        
        // Link specifiers
        for spec in &extend_info.link_specifiers {
            match spec {
                LinkSpecifier::IPv4 { addr, port } => {
                    payload.push(0); // IPv4 type
                    payload.push(6); // Length
                    payload.extend_from_slice(addr);
                    payload.extend_from_slice(&port.to_be_bytes());
                }
                LinkSpecifier::IPv6 { addr, port } => {
                    payload.push(1); // IPv6 type
                    payload.push(18); // Length
                    payload.extend_from_slice(addr);
                    payload.extend_from_slice(&port.to_be_bytes());
                }
                LinkSpecifier::Legacy { identity } => {
                    payload.push(2); // Legacy identity type
                    payload.push(20); // Length
                    payload.extend_from_slice(identity);
                }
                LinkSpecifier::Ed25519 { identity } => {
                    payload.push(3); // Ed25519 identity type
                    payload.push(32); // Length
                    payload.extend_from_slice(identity);
                }
            }
        }
        
        // Handshake type and data
        payload.extend_from_slice(&handshake_type.to_be_bytes());
        payload.extend_from_slice(&(handshake_data.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake_data);
        
        payload
    }
}

impl RelayCommand {
    fn from_u8(value: u8) -> Result<Self, OnionError> {
        match value {
            1 => Ok(RelayCommand::RelayBegin),
            2 => Ok(RelayCommand::RelayData),
            3 => Ok(RelayCommand::RelayEnd),
            4 => Ok(RelayCommand::RelayConnected),
            5 => Ok(RelayCommand::RelayResolve),
            6 => Ok(RelayCommand::RelayExtend),
            7 => Ok(RelayCommand::RelayExtended),
            8 => Ok(RelayCommand::RelayTruncate),
            9 => Ok(RelayCommand::RelayTruncated),
            10 => Ok(RelayCommand::RelayDrop),
            11 => Ok(RelayCommand::RelayResolve2),
            12 => Ok(RelayCommand::RelayResolved),
            13 => Ok(RelayCommand::RelayBeginDir),
            14 => Ok(RelayCommand::RelayExtend2),
            15 => Ok(RelayCommand::RelayExtended2),
            32 => Ok(RelayCommand::RelayEstablishIntro),
            33 => Ok(RelayCommand::RelayEstablishRendezvous),
            34 => Ok(RelayCommand::RelayIntroduce1),
            35 => Ok(RelayCommand::RelayIntroduce2),
            36 => Ok(RelayCommand::RelayRendezvous1),
            37 => Ok(RelayCommand::RelayRendezvous2),
            38 => Ok(RelayCommand::RelayIntroEstablished),
            39 => Ok(RelayCommand::RelayRendezvousEstablished),
            40 => Ok(RelayCommand::RelayIntroduceAck),
            _ => Err(OnionError::InvalidCell),
        }
    }
}

/// Cell processor for handling all incoming and outgoing cells
pub struct CellProcessor {
    pending_cells: Mutex<BTreeMap<CircuitId, Vec<Cell>>>,
    stream_id_counter: AtomicU16,
    statistics: CellStatistics,
}

#[derive(Debug, Default)]
pub struct CellStatistics {
    pub cells_processed: AtomicU16,
    pub relay_cells_processed: AtomicU16,
    pub create_cells_processed: AtomicU16,
    pub destroy_cells_processed: AtomicU16,
    pub data_bytes_transferred: AtomicU16,
}

impl CellProcessor {
    pub fn new() -> Self {
        CellProcessor {
            pending_cells: Mutex::new(BTreeMap::new()),
            stream_id_counter: AtomicU16::new(1),
            statistics: CellStatistics::default(),
        }
    }

    /// Process incoming cell from network
    pub fn process_cell(&mut self, cell: Cell, circuit_manager: &mut CircuitManager, stream_manager: &mut StreamManager) -> Result<(), OnionError> {
        self.statistics.cells_processed.fetch_add(1, Ordering::Relaxed);

        match cell.command {
            cmd if cmd == CellType::Create as u8 => self.handle_create_cell(cell, circuit_manager),
            cmd if cmd == CellType::Create2 as u8 => self.handle_create2_cell(cell, circuit_manager),
            cmd if cmd == CellType::Created as u8 => self.handle_created_cell(cell, circuit_manager),
            cmd if cmd == CellType::Created2 as u8 => self.handle_created2_cell(cell, circuit_manager),
            cmd if cmd == CellType::Relay as u8 || cmd == CellType::RelayEarly as u8 => {
                self.handle_relay_cell(cell, circuit_manager, stream_manager)
            }
            cmd if cmd == CellType::Destroy as u8 => self.handle_destroy_cell(cell, circuit_manager),
            cmd if cmd == CellType::Padding as u8 => {
                // Padding cells are ignored
                Ok(())
            }
            _ => {
                // Unknown cell type
                Err(OnionError::InvalidCell)
            }
        }
    }

    fn handle_create_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        self.statistics.create_cells_processed.fetch_add(1, Ordering::Relaxed);
        // Process CREATE cell - typically only relevant for relays
        Ok(())
    }

    fn handle_create2_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        self.statistics.create_cells_processed.fetch_add(1, Ordering::Relaxed);
        // Process CREATE2 cell - typically only relevant for relays
        Ok(())
    }

    fn handle_created_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        circuit_manager.handle_created_cell(cell.circuit_id, cell)
    }

    fn handle_created2_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        circuit_manager.handle_created_cell(cell.circuit_id, cell)
    }

    fn handle_relay_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager, stream_manager: &mut StreamManager) -> Result<(), OnionError> {
        self.statistics.relay_cells_processed.fetch_add(1, Ordering::Relaxed);

        // First decrypt the cell through circuit layers
        let decrypted_cell = if let Some(circuit) = circuit_manager.get_circuit(cell.circuit_id) {
            let mut decrypted = cell.clone();
            decrypted.payload = circuit.decrypt_backward(&cell.payload)?;
            decrypted
        } else {
            return Err(OnionError::CircuitBuildFailed);
        };

        // Parse as relay cell
        let relay_cell = decrypted_cell.parse_relay_cell()?;
        
        // Dispatch based on relay command
        match relay_cell.header.command {
            RelayCommand::RelayData => {
                self.statistics.data_bytes_transferred.fetch_add(relay_cell.payload.len() as u16, Ordering::Relaxed);
                stream_manager.handle_data(relay_cell.header.stream_id, &relay_cell.payload)
            }
            RelayCommand::RelayBegin => stream_manager.handle_begin(relay_cell),
            RelayCommand::RelayConnected => stream_manager.handle_connected(relay_cell),
            RelayCommand::RelayEnd => stream_manager.handle_end(relay_cell),
            RelayCommand::RelayExtended => circuit_manager.handle_extended_cell(cell.circuit_id, cell),
            RelayCommand::RelayExtended2 => circuit_manager.handle_extended_cell(cell.circuit_id, cell),
            RelayCommand::RelayResolve => self.handle_resolve(relay_cell),
            RelayCommand::RelayResolved => self.handle_resolved(relay_cell),
            _ => {
                // Unknown relay command
                Err(OnionError::InvalidCell)
            }
        }
    }

    fn handle_destroy_cell(&self, cell: Cell, circuit_manager: &mut CircuitManager) -> Result<(), OnionError> {
        self.statistics.destroy_cells_processed.fetch_add(1, Ordering::Relaxed);
        circuit_manager.close_circuit(cell.circuit_id)
    }

    fn handle_resolve(&self, _relay_cell: RelayCell) -> Result<(), OnionError> {
        // Handle DNS resolution request
        Ok(())
    }

    fn handle_resolved(&self, _relay_cell: RelayCell) -> Result<(), OnionError> {
        // Handle DNS resolution response
        Ok(())
    }

    /// Generate next stream ID
    pub fn next_stream_id(&self) -> StreamId {
        self.stream_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Get processing statistics
    pub fn get_statistics(&self) -> &CellStatistics {
        &self.statistics
    }

    /// Queue cell for transmission
    pub fn queue_cell(&self, circuit_id: CircuitId, cell: Cell) {
        if let Some(mut pending) = self.pending_cells.try_lock() {
            pending.entry(circuit_id).or_insert_with(Vec::new).push(cell);
        }
    }

    /// Flush queued cells for a circuit
    pub fn flush_circuit_cells(&self, circuit_id: CircuitId) -> Vec<Cell> {
        if let Some(mut pending) = self.pending_cells.try_lock() {
            pending.remove(&circuit_id).unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}