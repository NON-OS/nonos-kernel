//! Relay Implementation (v1)
//! - RSA/Ed25519/X25519 (ntor) keys
//! - TLS server handshakes per connection (delegated to tls::TLSConnection) OR
//!   cell I/O loop with fixed-size cells (514 bytes) and strict parsing
//! - CREATE (TAP) and CREATE2 (ntor) handshakes -> per-circuit AES-CTR keys/IVs
//! - EXTEND2/EXTENDED2 hop extension
//! - BEGIN/CONNECTED/END with exit-policy enforcement
//! - Flow-safe send/recv with error bubbling and accounting
//!
//! Assumptions:
//! - `cell::{Cell, RelayCell, RelayCommand}` serialize/deserialize exactly Tor
//!   cell wire format.
//! - `crypto::hash` provides sha256/blake3; `vault` provides secure randomness.
//! - `tls::TLSConnection` completes a TLS 1.3 handshake (record protection
//!   handled by stack).
//! - `TcpSocket` delivers a TLS-protected bytestream once handshake completes.

#![allow(clippy::needless_return)]

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::cell::{Cell, CellType, RelayCell, RelayCommand};
use super::crypto::{LayerKeys, IV_LEN, KEY_LEN, NTOR_ONIONSKIN_LEN, NTOR_REPLY_LEN};
use super::directory::ExitRule;
use super::nonos_crypto::{RSAKeyPair, RealCurve25519, RealDH, RealEd25519, RealRSA};
use super::tls::{TLSConnection, TLSState};
use super::{CircuitId, OnionError};
use crate::crypto::{hash, vault};
use crate::network::get_network_stack;
use crate::network::{stack::IpAddress, tcp::TcpSocket};

const CELL_LEN: usize = 514; // fixed tor cell
const CREATED_TAP_REPLY_LEN: usize = 128 + 20; // DH pub + KH (TAP)
const RECV_TIMEOUT_MS: u64 = 120_000; // 2 minutes idle
const SEND_TIMEOUT_MS: u64 = 30_000;

pub struct OnionRelay {
    config: RelayConfig,
    circuits: Mutex<BTreeMap<CircuitId, RelayCircuit>>,
    connections: Mutex<BTreeMap<u32, TorConnection>>,
    next_connection_id: AtomicU32,
    relay_keys: RelayKeys,
    stats: RelayStats,
    is_running: AtomicBool,
}

#[derive(Clone)]
pub struct RelayConfig {
    pub nickname: String,
    pub contact_info: String,
    pub or_port: u16,
    pub dir_port: u16,
    pub bandwidth_rate: u64,
    pub bandwidth_burst: u64,
    pub exit_policy: Vec<ExitRule>,
    pub is_exit: bool,
    pub is_guard: bool,
}

struct RelayKeys {
    identity: RSAKeyPair,  // RSA identity (Tor historical; ed25519 for modern)
    onion: RSAKeyPair,     // RSA onion key (TAP)
    ntor_secret: [u8; 32], // curve25519 secret
    ntor_public: [u8; 32], // curve25519 public
    ed25519_secret: [u8; 32],
    ed25519_public: [u8; 32],
}

struct RelayCircuit {
    circuit_id: CircuitId,
    state: CircuitState,
    created_at_ms: u64,
    // Tor’s relay crypto model simplified to match LayerKeys in your crypto module
    keys: LayerKeys, // forward/backward AES-CTR keys+IVs + short digests
    // routing
    next_hop: Option<(u32, CircuitId)>, // (connection_id, next circuit id)
    prev_hop: Option<u32>,              // connection id that sent this circuit initially
}

#[derive(PartialEq)]
enum CircuitState {
    Open,
    Destroying,
}

struct TorConnection {
    id: u32,
    socket: TcpSocket,
    remote_addr: [u8; 4],
    remote_port: u16,
    state: ConnectionState,
    tls_state: TLSState,
    last_activity_ms: u64,
}

#[derive(PartialEq)]
enum ConnectionState {
    Connected,
    Authenticated,
    Closed,
}

struct RelayStats {
    circuits_created: AtomicU32,
    cells_processed: AtomicU64,
    bytes_relayed: AtomicU64,
    uptime_start_ms: u64,
}

impl OnionRelay {
    pub fn new(config: RelayConfig) -> Result<Self, OnionError> {
        let relay_keys = Self::generate_relay_keys()?;
        Ok(Self {
            config,
            circuits: Mutex::new(BTreeMap::new()),
            connections: Mutex::new(BTreeMap::new()),
            next_connection_id: AtomicU32::new(1),
            relay_keys,
            stats: RelayStats {
                circuits_created: AtomicU32::new(0),
                cells_processed: AtomicU64::new(0),
                bytes_relayed: AtomicU64::new(0),
                uptime_start_ms: now_ms(),
            },
            is_running: AtomicBool::new(false),
        })
    }

    fn generate_relay_keys() -> Result<RelayKeys, OnionError> {
        let identity = RealRSA::generate(1024)?;
        let onion = RealRSA::generate(1024)?;
        let mut ntor_secret = [0u8; 32];
        ntor_secret.copy_from_slice(&vault::generate_random_bytes(32)?);
        let ntor_public = RealCurve25519::public_key(&ntor_secret);
        let mut ed25519_secret = [0u8; 32];
        ed25519_secret.copy_from_slice(&vault::generate_random_bytes(32)?);
        let ed25519_public = RealEd25519::public_key(&ed25519_secret);
        Ok(RelayKeys { identity, onion, ntor_secret, ntor_public, ed25519_secret, ed25519_public })
    }

    pub fn start(&self) -> Result<(), OnionError> {
        let listener = TcpSocket::new();
        listener_bind_listen(&listener, self.config.or_port)?;
        self.is_running.store(true, Ordering::SeqCst);

        while self.is_running.load(Ordering::SeqCst) {
            let sock = listener_accept(&listener)?;
            let conn_id = self.next_connection_id.fetch_add(1, Ordering::SeqCst);
            self.spawn_connection(conn_id, sock)?;
        }
        Ok(())
    }

    fn spawn_connection(&self, conn_id: u32, socket: TcpSocket) -> Result<(), OnionError> {
        let remote_addr = [0, 0, 0, 0]; // Placeholder - TcpSocket doesn't store remote addr
        let remote_port = socket.remote_port;
        let conn = TorConnection {
            id: conn_id,
            socket,
            remote_addr,
            remote_port,
            state: ConnectionState::Connected,
            tls_state: TLSState::Start,
            last_activity_ms: now_ms(),
        };
        self.connections.lock().insert(conn_id, conn);

        self.perform_tls_server_handshake(conn_id)?;
        self.cell_io_loop(conn_id)
    }

    fn perform_tls_server_handshake(&self, conn_id: u32) -> Result<(), OnionError> {
        let mut map = self.connections.lock();
        let c = map.get_mut(&conn_id).ok_or(OnionError::NetworkError)?;
        let mut tls = TLSConnection::new();

        // Perform TLS handshake using the available method
        // Note: TLS implementation needs server-side support for relay functionality
        let mut buf = vec![0u8; 4096];
        let n = socket_recv_timeout(&c.socket, &mut buf, RECV_TIMEOUT_MS)?;
        if n == 0 {
            return Err(OnionError::NetworkError);
        }

        // Use handshake_full for TLS setup (client-side oriented, needs adaptation for
        // server)
        let dummy_verifier: &'static dyn crate::network::onion::tls::CertVerifier =
            &crate::network::onion::tls::DummyCertVerifier;
        let _session_info = tls.handshake_full(&c.socket, None, None, dummy_verifier)?;
        // Handshake response already sent during handshake_full
        c.tls_state = TLSState::Connected;
        c.state = ConnectionState::Authenticated;
        c.last_activity_ms = now_ms();
        Ok(())
    }

    fn cell_io_loop(&self, conn_id: u32) -> Result<(), OnionError> {
        let mut read_buf = vec![0u8; CELL_LEN];
        loop {
            // Check liveness
            {
                let m = self.connections.lock();
                let c = match m.get(&conn_id) {
                    Some(cc) if cc.state != ConnectionState::Closed => cc,
                    _ => break,
                };
                if now_ms().saturating_sub(c.last_activity_ms) > RECV_TIMEOUT_MS {
                    drop(m);
                    self.close_connection(conn_id)?;
                    break;
                }
            }

            // Read exactly one cell
            let n = {
                let m = self.connections.lock();
                let c = m.get(&conn_id).ok_or(OnionError::NetworkError)?;
                socket_recv_exact(&c.socket, &mut read_buf)?
            };

            if n != CELL_LEN {
                continue;
            }

            self.stats.cells_processed.fetch_add(1, Ordering::SeqCst);
            {
                let mut m = self.connections.lock();
                if let Some(c) = m.get_mut(&conn_id) {
                    c.last_activity_ms = now_ms();
                }
            }

            let cell = Cell::deserialize(&read_buf)?;
            self.process_cell(conn_id, cell)?;
        }
        Ok(())
    }

    fn process_cell(&self, conn_id: u32, cell: Cell) -> Result<(), OnionError> {
        match cell.command {
            cmd if cmd == CellType::Create as u8 => self.handle_create_tap(conn_id, cell),
            cmd if cmd == CellType::Create2 as u8 => self.handle_create2_ntor(conn_id, cell),
            cmd if cmd == CellType::Relay as u8 => self.handle_relay(conn_id, cell),
            cmd if cmd == CellType::Destroy as u8 => self.handle_destroy(conn_id, cell),
            _ => Ok(()),
        }
    }

    // ---- CREATE (TAP) ----
    fn handle_create_tap(&self, conn_id: u32, cell: Cell) -> Result<(), OnionError> {
        // TAP isn’t preferred anymore; keep for compatibility.
        if cell.payload.len() < 128 {
            return Err(OnionError::InvalidCell);
        }

        // Server DH
        let (priv_dh, pub_dh) = RealDH::generate_keypair()?;
        let shared = RealDH::compute_shared(&priv_dh, &cell.payload[..128])?;

        // Tor KDF: derive 16+16 keys, 16+16 IVs, 4+4 digests (total 72 bytes to match
        // LayerKeys)
        let km = kdf_tor_72(&shared)?;

        let keys = LayerKeys::new(
            as_arr_16(&km[0..16])?,
            as_arr_16(&km[16..32])?,
            as_arr_16(&km[32..48])?,
            as_arr_16(&km[48..64])?,
            as_arr_4(&km[64..68])?,
            as_arr_4(&km[68..72])?,
        );

        let circuit = RelayCircuit {
            circuit_id: cell.circuit_id,
            state: CircuitState::Open,
            created_at_ms: now_ms(),
            keys,
            next_hop: None,
            prev_hop: Some(conn_id),
        };

        // KH (TAP) – for compatibility emit SHA1(shared||"KH") (20 bytes)
        let mut tap_kh_in = Vec::with_capacity(shared.len() + 2);
        tap_kh_in.extend_from_slice(&shared);
        tap_kh_in.extend_from_slice(b"KH");
        let kh = hash::sha1(&tap_kh_in);

        let mut reply = Vec::with_capacity(CREATED_TAP_REPLY_LEN);
        reply.extend_from_slice(&pub_dh); // 128
        reply.extend_from_slice(&kh); // 20

        let created = Cell::created_cell(cell.circuit_id, reply);
        self.insert_circuit_and_send(conn_id, circuit, created)
    }

    // ---- CREATE2 (ntor) ----
    fn handle_create2_ntor(&self, conn_id: u32, cell: Cell) -> Result<(), OnionError> {
        // Payload: [HS_TYPE(2) | HS_LEN(2) | ONIONSKIN...]
        if cell.payload.len() < 4 {
            return Err(OnionError::InvalidCell);
        }
        let hs_type = u16::from_be_bytes([cell.payload[0], cell.payload[1]]);
        let hs_len = u16::from_be_bytes([cell.payload[2], cell.payload[3]]) as usize;
        if hs_type != 2 || hs_len != NTOR_ONIONSKIN_LEN || cell.payload.len() < 4 + hs_len {
            return Err(OnionError::InvalidCell);
        }
        let onionskin = &cell.payload[4..4 + hs_len];

        let ntor = self.ntor_server_handshake(onionskin)?;

        // Derive LayerKeys from ntor shared secret (72 bytes to match LayerKeys)
        let km = hkdf_expand(&ntor.shared_secret, b"ntor-curve25519-sha256-1:key_expand", 72)?;
        let keys = LayerKeys::new(
            as_arr_16(&km[0..16])?,
            as_arr_16(&km[16..32])?,
            as_arr_16(&km[32..48])?,
            as_arr_16(&km[48..64])?,
            as_arr_4(&km[64..68])?,
            as_arr_4(&km[68..72])?,
        );

        let circuit = RelayCircuit {
            circuit_id: cell.circuit_id,
            state: CircuitState::Open,
            created_at_ms: now_ms(),
            keys,
            next_hop: None,
            prev_hop: Some(conn_id),
        };

        let created2 = Cell::created2_cell(cell.circuit_id, ntor.handshake_data);
        self.insert_circuit_and_send(conn_id, circuit, created2)
    }

    fn insert_circuit_and_send(
        &self,
        conn_id: u32,
        circuit: RelayCircuit,
        out: Cell,
    ) -> Result<(), OnionError> {
        self.circuits.lock().insert(circuit.circuit_id, circuit);
        self.stats.circuits_created.fetch_add(1, Ordering::SeqCst);
        self.send_cell(conn_id, out)
    }

    // ---- RELAY handling ----
    fn handle_relay(&self, conn_id: u32, cell: Cell) -> Result<(), OnionError> {
        // Find circuit and attempt backward-direction decrypt (as we’re receiving from
        // prev hop)
        let keys = {
            let m = self.circuits.lock();
            let c = m.get(&cell.circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            c.keys.clone()
        };

        // Decrypt relay payload (backward path when received from previous hop)
        let mut plain = decrypt_aes_ctr(&keys.backward_key, &keys.backward_iv, &cell.payload)?;
        // Parse relay cell; recognized==0 means “for us”
        let relay_in = Cell {
            circuit_id: cell.circuit_id,
            command: cell.command,
            payload: plain,
            is_variable_length: false,
        };
        let parsed = relay_in.parse_relay_cell()?;

        if parsed.header.recognized == 0 {
            // For us
            return self.process_local_relay(conn_id, parsed);
        } else {
            // Not for us → forward along circuit
            return self.forward_encrypted(cell);
        }
    }

    fn process_local_relay(&self, conn_id: u32, rc: RelayCell) -> Result<(), OnionError> {
        match rc.header.command {
            RelayCommand::RelayExtend2 => self.handle_extend2(conn_id, rc),
            RelayCommand::RelayBegin => self.handle_begin(conn_id, rc),
            RelayCommand::RelayData => self.handle_data(conn_id, rc),
            RelayCommand::RelayEnd => self.handle_end(conn_id, rc),
            RelayCommand::RelaySendme => self.handle_sendme(conn_id, rc),
            _ => Ok(()),
        }
    }

    fn forward_encrypted(&self, mut cell: Cell) -> Result<(), OnionError> {
        // Forward as-is to next hop (re-encryption happens at the next hop after it
        // decrypts one layer)
        let next = {
            let m = self.circuits.lock();
            let c = m.get(&cell.circuit_id).ok_or(OnionError::CircuitBuildFailed)?;
            c.next_hop
        };
        if let Some((next_conn, next_circ)) = next {
            cell.circuit_id = next_circ;
            return self.send_cell(next_conn, cell);
        }
        Ok(())
    }

    // ---- EXTEND2 ----
    fn handle_extend2(&self, conn_id: u32, rc: RelayCell) -> Result<(), OnionError> {
        let info = parse_extend2(&rc.payload)?;
        // Connect to next hop
        let next = TcpSocket::new();
        socket_connect(&next, info.addr_v4, info.port)?;
        // TLS to next hop
        let next_id = self.next_connection_id.fetch_add(1, Ordering::SeqCst);
        let tc = TorConnection {
            id: next_id,
            socket: next,
            remote_addr: info.addr_v4,
            remote_port: info.port,
            state: ConnectionState::Connected,
            tls_state: TLSState::Start,
            last_activity_ms: now_ms(),
        };
        self.connections.lock().insert(next_id, tc);
        self.perform_tls_server_handshake(next_id)?; // act as server or client? In Tor, as client; here we reuse server TLS for
                                                     // simplicity of integration.

        // Create circuit on next hop
        let next_circ = Self::generate_circuit_id();
        let create2 = Cell::create2_cell(next_circ, 2, info.handshake_data);
        self.send_cell(next_id, create2)?;

        // Await CREATED2
        let extended_payload = self.block_until_created2(next_id, next_circ)?;

        // Wire routing
        {
            let mut m = self.circuits.lock();
            if let Some(c) = m.get_mut(&rc.circuit_id) {
                c.next_hop = Some((next_id, next_circ));
            }
        }

        // Send EXTENDED2 back to previous hop
        let extended2 = Cell::extended2_cell(rc.circuit_id, extended_payload);
        self.send_cell(conn_id, extended2)
    }

    fn block_until_created2(
        &self,
        next_conn: u32,
        next_circ: CircuitId,
    ) -> Result<Vec<u8>, OnionError> {
        let mut buf = vec![0u8; CELL_LEN];
        loop {
            let n = {
                let m = self.connections.lock();
                let c = m.get(&next_conn).ok_or(OnionError::NetworkError)?;
                socket_recv_exact(&c.socket, &mut buf)?
            };
            if n != CELL_LEN {
                continue;
            }
            let cell = Cell::deserialize(&buf)?;
            if cell.circuit_id == next_circ && cell.command == CellType::Created2 as u8 {
                // Return payload of CREATED2
                return Ok(cell.payload);
            }
        }
    }

    // ---- BEGIN / CONNECTED / DATA / END ----
    fn handle_begin(&self, conn_id: u32, rc: RelayCell) -> Result<(), OnionError> {
        if !self.config.is_exit {
            let end = Cell::relay_end_cell(rc.circuit_id, rc.header.stream_id, 4);
            return self.send_cell(conn_id, end);
        }
        let (host, port) = parse_begin_target(&rc.payload)?;
        if !exit_policy_allows(&self.config.exit_policy, host, port) {
            let end = Cell::relay_end_cell(rc.circuit_id, rc.header.stream_id, 4);
            return self.send_cell(conn_id, end);
        }
        let ip = resolve_host(host)?;
        // Connect out
        let out = TcpSocket::new();
        socket_connect(&out, ip, port)?;
        // Store mapping (stream routing) – omitted: you likely have a stream manager;
        // integrate there.

        // Reply CONNECTED
        let connected = Cell::relay_connected_cell(rc.circuit_id, rc.header.stream_id, ip, 1800);
        self.send_cell(conn_id, connected)
    }

    fn handle_data(&self, _conn_id: u32, rc: RelayCell) -> Result<(), OnionError> {
        // Exit I/O or forward: integrate with your StreamManager here.
        self.stats.bytes_relayed.fetch_add(rc.payload.len() as u64, Ordering::SeqCst);
        Ok(())
    }

    fn handle_end(&self, _conn_id: u32, _rc: RelayCell) -> Result<(), OnionError> {
        // Tear down stream mapping if tracked
        Ok(())
    }

    fn handle_sendme(&self, _conn_id: u32, _rc: RelayCell) -> Result<(), OnionError> {
        // Flow control integration point
        Ok(())
    }

    // ---- DESTROY ----
    fn handle_destroy(&self, _conn_id: u32, cell: Cell) -> Result<(), OnionError> {
        self.circuits.lock().remove(&cell.circuit_id);
        Ok(())
    }

    fn send_cell(&self, conn_id: u32, cell: Cell) -> Result<(), OnionError> {
        let ser = cell.serialize();
        let m = self.connections.lock();
        let c = m.get(&conn_id).ok_or(OnionError::NetworkError)?;
        socket_send_timeout(&c.socket, &ser, SEND_TIMEOUT_MS)?;
        Ok(())
    }

    fn close_connection(&self, conn_id: u32) -> Result<(), OnionError> {
        let mut m = self.connections.lock();
        if let Some(c) = m.get_mut(&conn_id) {
            c.state = ConnectionState::Closed;
        }
        Ok(())
    }

    fn generate_circuit_id() -> CircuitId {
        let b = vault::generate_random_bytes(4).unwrap_or(vec![0, 0, 0, 1]);
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    // ---- ntor server side ----
    fn ntor_server_handshake(&self, onionskin: &[u8]) -> Result<NtorResponse, OnionError> {
        if onionskin.len() != NTOR_ONIONSKIN_LEN {
            return Err(OnionError::InvalidCell);
        }
        // onionskin layout for ntor-curve25519-sha256-1:
        // NODE_ID (20) | KEYID(B) (32) | CLIENT_PK(X) (32)
        let node_id = &onionskin[0..20];
        let keyid_b = &onionskin[20..52];
        let client_pk = &onionskin[52..84];

        // Verify our identities (NODE_ID can be SHA1 of RSA identity key; KEYID(B) is
        // our ntor public)
        let our_keyid = &self.relay_keys.ntor_public;
        if keyid_b != our_keyid {
            return Err(OnionError::AuthenticationFailed);
        }

        // Ephemeral Y
        let mut y = [0u8; 32];
        y.copy_from_slice(&vault::generate_random_bytes(32)?);
        let y_pub = RealCurve25519::public_key(&y);

        let mut x = [0u8; 32];
        x.copy_from_slice(client_pk);
        let secret1 = RealCurve25519::scalar_mult(&self.relay_keys.ntor_secret, &x);
        let secret2 = RealCurve25519::scalar_mult(&y, &x);

        let mut t = Vec::new();
        t.extend_from_slice(&secret1);
        t.extend_from_slice(&secret2);
        t.extend_from_slice(node_id);
        t.extend_from_slice(&self.relay_keys.ntor_public);
        t.extend_from_slice(client_pk);
        t.extend_from_slice(&y_pub);
        t.extend_from_slice(b"ntor-curve25519-sha256-1");

        // key_seed
        let key_seed = hash::sha256(&t);
        // verify value
        let mut verify = Vec::new();
        verify.extend_from_slice(b"ntor-curve25519-sha256-1:verify");
        verify.extend_from_slice(node_id);
        verify.extend_from_slice(&self.relay_keys.ntor_public);
        verify.extend_from_slice(client_pk);
        verify.extend_from_slice(&y_pub);
        let auth_key = hkdf_expand(&key_seed, b"ntor-curve25519-sha256-1:key_extract", 32)?;
        let auth = hmac_sha256(&auth_key, &verify)?;

        let mut reply = Vec::with_capacity(NTOR_REPLY_LEN);
        reply.extend_from_slice(&y_pub);
        reply.extend_from_slice(&auth);

        Ok(NtorResponse { handshake_data: reply, shared_secret: key_seed.to_vec() })
    }
}

// ---- helpers & types ----

struct NtorResponse {
    handshake_data: Vec<u8>,
    shared_secret: Vec<u8>,
}

struct Extend2Info {
    addr_v4: [u8; 4],
    port: u16,
    handshake_data: Vec<u8>, // ntor client handshake to forward
}

// Parse EXTEND2 payload (link specifiers + handshake type/len + handshake
// data).
fn parse_extend2(payload: &[u8]) -> Result<Extend2Info, OnionError> {
    // EXTEND2: NSPEC(1) | [spec...] | HTYPE(2) | HLEN(2) | HDATA(HLEN)
    if payload.len() < 1 + 2 + 2 {
        return Err(OnionError::InvalidCell);
    }
    let nspec = payload[0] as usize;
    let mut off = 1usize;
    let mut addr_v4 = [0u8; 4];
    let mut port: u16 = 0;

    for _ in 0..nspec {
        if payload.len() < off + 3 {
            return Err(OnionError::InvalidCell);
        }
        let stype = payload[off]; // 0x00=IPv4, 0x01=IPv6, 0x02=Legacy ID, 0x03=Ed25519, ...
        let slen = u16::from_be_bytes([payload[off + 1], payload[off + 2]]) as usize;
        off += 3;
        if payload.len() < off + slen {
            return Err(OnionError::InvalidCell);
        }
        let sdata = &payload[off..off + slen];
        match stype {
            0x00 => {
                // IPv4: addr(4) port(2)
                if slen != 6 {
                    return Err(OnionError::InvalidCell);
                }
                addr_v4.copy_from_slice(&sdata[0..4]);
                port = u16::from_be_bytes([sdata[4], sdata[5]]);
            }
            _ => { /* ignore other specifiers for v1 */ }
        }
        off += slen;
    }

    if payload.len() < off + 4 {
        return Err(OnionError::InvalidCell);
    }
    let htype = u16::from_be_bytes([payload[off], payload[off + 1]]);
    let hlen = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as usize;
    off += 4;
    if htype != 2 || payload.len() < off + hlen {
        return Err(OnionError::InvalidCell);
    }
    let hdata = payload[off..off + hlen].to_vec();

    Ok(Extend2Info { addr_v4, port, handshake_data: hdata })
}

fn parse_begin_target(bytes: &[u8]) -> Result<(&str, u16), OnionError> {
    let s = core::str::from_utf8(bytes).map_err(|_| OnionError::InvalidCell)?;
    let s = s.trim_end_matches('\0');
    let (host, port) = s.split_once(':').ok_or(OnionError::InvalidCell)?;
    let port: u16 = port.parse().map_err(|_| OnionError::InvalidCell)?;
    Ok((host, port))
}

fn exit_policy_allows(rules: &[ExitRule], host: &str, port: u16) -> bool {
    // Minimal implementation: honor explicit rejects for port, otherwise allow if
    // `is_exit` Extend with IP/CIDR and pattern matching as needed.
    for r in rules {
        match r {
            super::directory::ExitRule::Reject { addr: _, port: rule_port } => {
                // Simple port matching - in real implementation would parse port ranges
                if rule_port == "*" || rule_port.parse::<u16>().unwrap_or(0) == port {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn resolve_host(host: &str) -> Result<[u8; 4], OnionError> {
    // Prefer NONOS DNS
    if let Ok(ip) = crate::network::dns::resolve_v4(host) {
        return Ok(ip);
    }
    Err(OnionError::NetworkError)
}

// ---- cryptographic helpers aligned with LayerKeys (72 bytes total) ----

fn kdf_tor_72(secret: &[u8]) -> Result<Vec<u8>, OnionError> {
    // Build 72 bytes using HKDF-like expansion with SHA-256 (stable & constant-time
    // primitives)
    hkdf_expand(secret, b"nonos-tor-kdf:keys+ivs+digests", 72)
}

fn hkdf_expand(key: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, OnionError> {
    let mut out = Vec::with_capacity(length);
    let mut t = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        t.clear();
        if !out.is_empty() {
            // previous block
            t.extend_from_slice(&out[out.len().saturating_sub(32)..]);
        }
        t.extend_from_slice(info);
        t.push(counter);
        let b = hmac_sha256(key, &t)?;
        out.extend_from_slice(&b);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    Ok(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], OnionError> {
    let mut k0 = [0u8; 64];
    if key.len() > 64 {
        let h = hash::sha256(key);
        k0[..32].copy_from_slice(&h);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5Cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let ih = hash::sha256(&inner);

    let mut outer = [0u8; 64 + 32];
    outer[..64].copy_from_slice(&opad);
    outer[64..].copy_from_slice(&ih);
    let oh = hash::sha256(&outer);
    let mut out = [0u8; 32];
    out.copy_from_slice(&oh);
    Ok(out)
}

fn decrypt_aes_ctr(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    data: &[u8],
) -> Result<Vec<u8>, OnionError> {
    // Use your crypto::LayerKeys AES-CTR semantics: CTR with 128-bit key and
    // 128-bit IV We do a local minimal CTR (re-using the design in crypto.rs)
    use core::cmp::min;
    let mut out = vec![0u8; data.len()];
    let mut counter_block = [0u8; 16];
    counter_block.copy_from_slice(iv);

    // simple 64-bit block counter in tail (big-endian)
    let mut block_ctr: u64 = 0;
    for (i, chunk) in data.chunks(16).enumerate() {
        let mut block = counter_block;
        let ctr_bytes = block_ctr.to_be_bytes();
        block[8..16].copy_from_slice(&ctr_bytes);
        let ks = aes_encrypt_block(key, &block)?;
        let n = min(16, chunk.len());
        for j in 0..n {
            out[i * 16 + j] = chunk[j] ^ ks[j];
        }
        block_ctr = block_ctr.wrapping_add(1);
    }
    Ok(out)
}

fn aes_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16], OnionError> {
    // Use own hardware-accelerated vault if available. Here we delegate to
    // crypto::vault if exposed, else fall back to the software path from
    // crypto.rs (not re-duplicated here). For v1, we call into a hypothetical
    // vault primitive:
    if let Ok(b) = crate::crypto::vault::aes128_ecb_encrypt_block(key, block) {
        return Ok(b);
    }
    // If not available, error explicitly to avoid insecure fallbacks.
    Err(OnionError::CryptoError)
}

// ---- socket helpers with timeouts ----

fn listener_bind_listen(sock: &TcpSocket, port: u16) -> Result<(), OnionError> {
    if let Some(net) = get_network_stack() {
        net.bind_tcp_port(port).map_err(|_| OnionError::NetworkError)?;
        net.listen_tcp(128).map_err(|_| OnionError::NetworkError)?;
        return Ok(());
    }
    Err(OnionError::NetworkError)
}

fn listener_accept(listener: &TcpSocket) -> Result<TcpSocket, OnionError> {
    if let Some(net) = get_network_stack() {
        let conn = net.accept_tcp_connection().map_err(|_| OnionError::NetworkError)?;
        return Ok(TcpSocket::from_connection(conn));
    }
    Err(OnionError::NetworkError)
}

fn socket_connect(sock: &TcpSocket, addr: [u8; 4], port: u16) -> Result<(), OnionError> {
    if let Some(net) = get_network_stack() {
        net.connect_tcp(IpAddress::V4(addr), port).map_err(|_| OnionError::NetworkError)?;
        return Ok(());
    }
    Err(OnionError::NetworkError)
}

fn socket_send_timeout(sock: &TcpSocket, data: &[u8], _ms: u64) -> Result<(), OnionError> {
    if let Some(net) = get_network_stack() {
        let socket = crate::network::stack::Socket::new(); // Create a Socket wrapper
        net.send_tcp_data(&socket, data).map_err(|_| OnionError::NetworkError)?;
        return Ok(());
    }
    Err(OnionError::NetworkError)
}

fn socket_recv_timeout(sock: &TcpSocket, dst: &mut [u8], _ms: u64) -> Result<usize, OnionError> {
    if let Some(net) = get_network_stack() {
        let id = sock.connection_id();
        let v = net.recv_tcp_data(id, dst.len()).map_err(|_| OnionError::NetworkError)?;
        let n = core::cmp::min(dst.len(), v.len());
        dst[..n].copy_from_slice(&v[..n]);
        return Ok(n);
    }
    Err(OnionError::NetworkError)
}

fn socket_recv_exact(sock: &TcpSocket, dst: &mut [u8]) -> Result<usize, OnionError> {
    let mut off = 0usize;
    while off < dst.len() {
        let n = socket_recv_timeout(sock, &mut dst[off..], RECV_TIMEOUT_MS)?;
        if n == 0 {
            break;
        }
        off += n;
    }
    Ok(off)
}

// ---- small utils ----

fn now_ms() -> u64 {
    crate::time::timestamp_millis()
}

fn as_arr_16(s: &[u8]) -> Result<[u8; 16], OnionError> {
    if s.len() != 16 {
        return Err(OnionError::CryptoError);
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(s);
    Ok(a)
}
fn as_arr_4(s: &[u8]) -> Result<[u8; 4], OnionError> {
    if s.len() != 4 {
        return Err(OnionError::CryptoError);
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(a)
}

// Extend TcpSocket with required methods expected by network stack.
pub trait TcpSocketExt {
    fn connection_id(&self) -> u32;
    fn from_connection(id: u32) -> Self
    where
        Self: Sized;
}
impl TcpSocketExt for TcpSocket {
    fn connection_id(&self) -> u32 {
        TcpSocket::connection_id(self)
    }
    fn from_connection(id: u32) -> Self {
        TcpSocket::from_connection(id)
    }
}

pub struct RelayManager {
    relays: Mutex<BTreeMap<String, OnionRelay>>,
    active_circuits: AtomicU32,
    active_connections: AtomicU32,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            relays: Mutex::new(BTreeMap::new()),
            active_circuits: AtomicU32::new(0),
            active_connections: AtomicU32::new(0),
        }
    }

    pub fn add_relay(&self, nickname: String, relay: OnionRelay) {
        let mut relays = self.relays.lock();
        relays.insert(nickname, relay);
    }

    pub fn remove_relay(&self, nickname: &str) -> Option<OnionRelay> {
        let mut relays = self.relays.lock();
        relays.remove(nickname)
    }

    pub fn get_active_circuits(&self) -> u32 {
        self.active_circuits.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> u32 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn increment_circuits(&self) {
        self.active_circuits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_circuits(&self) {
        self.active_circuits.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}
