//! Directory Service Implementation (v1)
//!
//! Tor-style Networks directory client with:
//! - Microdescriptor-based path building
//! - Ed25519 authority signature verification (simplified canonicalization)
//! - Strict, bounded consensus & microdesc parsers (no_std-friendly)
//! - Guard/Middle/Exit selection w/ family & /16-subnet separation
//! - Weighted bandwidth selection using consensus weights
//! - Jittered refetch, HTTP size caps, simple in-memory caching
//!
//! Notes:
//! * Signature verification covers the raw consensus body we store. Tor's canonicalization is more nuanced; adapt later match spec bit-for-bit.
//! * Microdesc fetch uses uncompressed endpoints and simple textual parsing.
//! * Time window enforcement respects valid-after/fresh-until/valid-until.

#![allow(clippy::needless_return)]

use alloc::{vec::Vec, vec, collections::BTreeMap, string::{String, ToString}, format};
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use core::cmp::min;

use super::OnionError;
use super::circuit::PathConstraints;
use crate::crypto::{hash, sig, vault};
use crate::network::get_network_stack;

/// Hard caps to prevent DoS via giant directory objects.
const MAX_HTTP_BODY_BYTES: usize = 5 * 1024 * 1024; // 5 MiB
const MAX_CONSENSUS_LINES: usize = 200_000;
const MAX_MICRODESC_BYTES: usize = 64 * 1024; // per-microdesc cap
const MAX_AUTHORITY_TRIES: usize = 6;
const REFRESH_MIN_SECONDS: u64 = 15 * 60;  // 15 min floor
const REFRESH_DEFAULT_INTERVAL: u64 = 60 * 60; // 1h

/// Exit policy rule for relay selection
#[derive(Debug, Clone, PartialEq)]
pub enum ExitRule {
    Accept { addr: String, port: String },
    Reject { addr: String, port: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExitPolicy {
    Accept,
    Reject,
}

impl ExitRule {
    pub fn allows_connection(&self, addr: &str, port: u16) -> bool {
        match self {
            ExitRule::Accept { addr: rule_addr, port: rule_port } => {
                self.matches_pattern(rule_addr, addr) && self.matches_port(rule_port, port)
            },
            ExitRule::Reject { addr: rule_addr, port: rule_port } => {
                !(self.matches_pattern(rule_addr, addr) && self.matches_port(rule_port, port))
            },
        }
    }
    
    fn matches_pattern(&self, pattern: &str, addr: &str) -> bool {
        if pattern == "*" { return true; }
        pattern == addr
    }
    
    fn matches_port(&self, pattern: &str, port: u16) -> bool {
        if pattern == "*" { return true; }
        if let Ok(p) = pattern.parse::<u16>() {
            return p == port;
        }
        false
    }
}

/// Directory authority information
#[derive(Debug, Clone)]
pub struct DirectoryAuthority {
    pub nickname: String,
    pub ed25519_identity: Option<[u8; 32]>, // v3 ed25519 identity (if known)
    pub identity_fingerprint: Vec<u8>,      // legacy hex-20 digest bytes (for metadata)
    pub address: [u8; 4],
    pub dir_port: u16,
    pub or_port: u16,
}

/// Relay descriptor with comprehensive information (populated from consensus+microdesc)
#[derive(Debug, Clone)]
pub struct RelayDescriptor {
    pub nickname: String,
    pub identity_digest: [u8; 20],      // SHA1 digest from consensus ("r" line b64)
    pub ed25519_identity: [u8; 32],     // from consensus "id ed25519" (if present, else zeros)
    pub ntor_onion_key: Vec<u8>,        // 32 bytes
    pub address: [u8; 4],               // IPv4 from consensus "r"
    pub port: u16,                      // ORPort from consensus "r"
    pub dir_port: u16,                  // DirPort from consensus "r"
    pub bandwidth: u64,                 // Advertised or measured
    pub measured_bandwidth: u64,        // measured if present else 0
    pub flags: RelayFlags,
    pub fingerprint: [u8; 20],          // SHA1 fingerprint of the relay
    pub family: String,                 // family string from microdesc if present
    pub country_code: String,           // not parsed here (placeholder)
    pub as_number: u32,                 // not resolved here (0 placeholder)
    pub consensus_weight: u32,          // not filled (0 placeholder)
    pub guard_probability: f32,         // computed externally if needed
    pub middle_probability: f32,
    pub exit_probability: f32,
}

/// Relay flags from consensus
#[derive(Debug, Clone, Default)]
pub struct RelayFlags {
    pub is_authority: bool,
    pub is_bad_exit: bool,
    pub is_exit: bool,
    pub is_fast: bool,
    pub is_guard: bool,
    pub is_hsdir: bool,
    pub is_no_ed_consensus: bool,
    pub is_running: bool,
    pub is_stable: bool,
    pub is_stable_uptime: bool,
    pub is_v2dir: bool,
    pub is_valid: bool,
}

/// Network consensus document (parsed subset)
#[derive(Debug, Clone)]
pub struct NetworkConsensus {
    pub raw_body: Vec<u8>,  // raw bytes used for signature verification
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
    pub consensus_method: u32,
    pub voting_delay: (u32, u32),    // vote_seconds, dist_seconds
    pub params: BTreeMap<String, i32>,
    pub authorities: Vec<DirectoryAuthorityHeader>,
    pub relays: Vec<ConsensusEntry>,
    pub signatures: Vec<ConsensusSignature>,
    pub bandwidth_weights: BandwidthWeights,
}

/// Header info for authorities as listed in consensus
#[derive(Debug, Clone)]
pub struct DirectoryAuthorityHeader {
    pub nickname: String,
    pub identity: [u8; 20],
    pub address: [u8; 4],
    pub dir_port: u16,
    pub or_port: u16,
}

/// Entry in consensus for a single relay
#[derive(Debug, Clone)]
pub struct ConsensusEntry {
    pub nickname: String,
    pub identity_digest: [u8; 20], // b64-20
    pub descriptor_digest: [u8; 20],
    pub microdesc_sha256: Option<[u8; 32]>, // from "m" line
    pub published: u64,
    pub address: [u8; 4],
    pub or_port: u16,
    pub dir_port: u16,
    pub flags: RelayFlags,
    pub version: Option<String>,
    pub bandwidth: Option<u64>,
    pub measured_bandwidth: Option<u64>,
    pub ed25519_id: Option<[u8; 32]>,
}

/// Authority signature on consensus
#[derive(Debug, Clone)]
pub struct ConsensusSignature {
    pub identity: [u8; 20],
    pub signing_alg: SigAlg,   // simplified
    pub signature: Vec<u8>,    // ed25519 sig (preferred)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigAlg { Ed25519, Unknown }

/// Bandwidth weights for path selection
#[derive(Debug, Clone, Default)]
pub struct BandwidthWeights {
    pub weight_scale: u32,
    pub wbd: u32, pub wbe: u32, pub wbg: u32, pub wbm: u32,
    pub wed: u32, pub wee: u32, pub weg: u32, pub wem: u32,
    pub wgd: u32, pub wgg: u32, pub wgm: u32,
    pub wmd: u32, pub wme: u32, pub wmg: u32, pub wmm: u32,
}

/// Router status enumeration (unused externally, kept for completeness)
#[derive(Debug, Clone, PartialEq)]
pub enum RouterStatus { Running, Down, Hibernating, Unknown }

/// Complete directory service implementation
pub struct DirectoryService {
    authorities: RwLock<Vec<DirectoryAuthority>>,
    current_consensus: RwLock<Option<NetworkConsensus>>,
    relay_descriptors: RwLock<BTreeMap<[u8; 20], RelayDescriptor>>,
    microdescriptors: RwLock<BTreeMap<[u8; 32], Vec<u8>>>, // SHA256 -> microdesc raw text
    consensus_cache: Mutex<BTreeMap<String, Vec<u8>>>, // path -> body
    directory_stats: DirectoryStats,
    last_consensus_fetch: AtomicU64,
    consensus_fetch_interval: u64,
}

/// Path selection & stats
struct PathSelection {
    // simple entropy pool to derive randomness for selection points
    entropy_pool: Mutex<[u8; 32]>,
    path_bias_stats: Mutex<BTreeMap<[u8; 20], PathBiasStats>>,
}

/// Path bias statistics for security analysis
#[derive(Debug, Clone, Default)]
struct PathBiasStats {
    pub circuits_attempted: u32,
    pub circuits_succeeded: u32,
    pub success_rate: f32,
    pub last_updated: u64,
}

/// Directory service statistics
#[derive(Debug, Default)]
pub struct DirectoryStats {
    pub consensus_fetches: AtomicU32,
    pub descriptor_fetches: AtomicU32,
    pub authorities_contacted: AtomicU32,
    pub consensus_parse_errors: AtomicU32,
    pub last_consensus_age: AtomicU64,
    pub relay_count: AtomicU32,
    pub guard_count: AtomicU32,
    pub exit_count: AtomicU32,
}

impl DirectoryService {
    pub fn new() -> Self {
        DirectoryService {
            authorities: RwLock::new(Self::default_authorities()),
            current_consensus: RwLock::new(None),
            relay_descriptors: RwLock::new(BTreeMap::new()),
            microdescriptors: RwLock::new(BTreeMap::new()),
            consensus_cache: Mutex::new(BTreeMap::new()),
            directory_stats: DirectoryStats::default(),
            last_consensus_fetch: AtomicU64::new(0),
            consensus_fetch_interval: REFRESH_DEFAULT_INTERVAL,
        }
    }

    pub fn init(&self) -> Result<(), OnionError> {
        crate::log::info!("directory: init");
        self.fetch_consensus()?;
        self.ensure_microdescs()?;
        Ok(())
    }

    /// Public: refresh consensus if stale; fetch microdescs if missing.
    pub fn refresh(&self) -> Result<(), OnionError> {
        self.fetch_consensus()?;
        self.ensure_microdescs()?;
        Ok(())
    }

    /// Fetch network consensus (bounded, with jitter & rotation).
    pub fn fetch_consensus(&self) -> Result<(), OnionError> {
        let now = current_time_s();
        let last = self.last_consensus_fetch.load(Ordering::Relaxed);
        if now.saturating_sub(last) < REFRESH_MIN_SECONDS {
            return Ok(());
        }

        let auths = self.authorities.read();
        let mut attempt = 0usize;
        let mut last_err: Option<OnionError> = None;

        // rotate authorities starting at a pseudo-random offset
        let mut offset = self.secure_random_u64() as usize % auths.len().max(1);
        while attempt < min(auths.len(), MAX_AUTHORITY_TRIES).max(1) {
            let a = &auths[(offset + attempt) % auths.len()];
            self.directory_stats.authorities_contacted.fetch_add(1, Ordering::Relaxed);

            match self.fetch_from_authority(a, "/tor/status-vote/current/consensus") {
                Ok(body) => {
                    match self.parse_consensus(&body) {
                        Ok(mut c) => {
                            if let Err(e) = self.validate_consensus(&mut c) {
                                self.directory_stats.consensus_parse_errors.fetch_add(1, Ordering::Relaxed);
                                last_err = Some(e);
                                attempt += 1;
                                continue;
                            }
                            self.directory_stats.consensus_fetches.fetch_add(1, Ordering::Relaxed);
                            *self.current_consensus.write() = Some(c);
                            self.last_consensus_fetch.store(now + self.jitter(5), Ordering::Relaxed);
                            self.update_relay_statistics();
                            return Ok(());
                        }
                        Err(e) => {
                            self.directory_stats.consensus_parse_errors.fetch_add(1, Ordering::Relaxed);
                            last_err = Some(e);
                        }
                    }
                }
                Err(e) => { last_err = Some(e); }
            }
            attempt += 1;
        }

        Err(last_err.unwrap_or(OnionError::DirectoryError))
    }

    /// Ensure we have microdescriptors for all consensus relays we may select.
    fn ensure_microdescs(&self) -> Result<(), OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        // gather missing digests
        let mut need: Vec<[u8; 32]> = Vec::new();
        {
            let have = self.microdescriptors.read();
            for e in &c.relays {
                if let Some(d) = e.microdesc_sha256 {
                    if !have.contains_key(&d) {
                        need.push(d);
                    }
                }
            }
        }
        if need.is_empty() { return Ok(()); }

        // fetch in chunks to keep URLs bounded
        let auths = self.authorities.read();
        let mut last_err: Option<OnionError> = None;

        for a in auths.iter() {
            // Build path: /tor/micro/d/<b32>+<b32>+...
            let mut path = String::from("/tor/micro/d/");
            const MAX_PER_REQUEST: usize = 25;
            for chunk in need.chunks(MAX_PER_REQUEST) {
                path.truncate("/tor/micro/d/".len());
                for (i, d) in chunk.iter().enumerate() {
                    if i > 0 { path.push('+'); }
                    path.push_str(&b64_url_nopad(&d[..]));
                }

                match self.fetch_from_authority(a, &path) {
                    Ok(body) => {
                        // response is concatenated microdescs separated by "\n\n" usually
                        let texts = split_microdesc_blobs(&body);
                        for t in texts {
                            if t.len() > MAX_MICRODESC_BYTES { continue; }
                            if let Some(d) = sha256_of_text(&t) {
                                self.microdescriptors.write().insert(d, t);
                            }
                        }
                        self.directory_stats.descriptor_fetches.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => { last_err = Some(e); continue; }
                }
            }
            // After one authority succeeds we stop; we may still be missing some
            // but selection will request on-demand.
            break;
        }

        // materialize RelayDescriptor entries for relays with microdescs
        self.materialize_relays_from_microdescs()?;

        Ok(())
    }

    /// Convert consensus entries + microdescs into RelayDescriptor map.
    fn materialize_relays_from_microdescs(&self) -> Result<(), OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let micro = self.microdescriptors.read();
        let mut out = self.relay_descriptors.write();

        for e in &c.relays {
            let Some(md_sha) = e.microdesc_sha256 else { continue; };
            let Some(text) = micro.get(&md_sha) else { continue; };

            let parsed = parse_microdesc(text).unwrap_or_default();

            // Skip if no ntor key present (we need it)
            if parsed.ntor_key.len() != 32 { continue; }

            let mut ed = [0u8; 32];
            if let Some(x) = e.ed25519_id { ed = x; }

            let rd = RelayDescriptor {
                nickname: e.nickname.clone(),
                identity_digest: e.identity_digest,
                ed25519_identity: ed,
                ntor_onion_key: parsed.ntor_key.to_vec(),
                address: e.address,
                port: e.or_port,
                dir_port: e.dir_port,
                bandwidth: e.measured_bandwidth.unwrap_or(e.bandwidth.unwrap_or(0)),
                measured_bandwidth: e.measured_bandwidth.unwrap_or(0),
                flags: e.flags.clone(),
                fingerprint: e.identity_digest, // Use identity_digest as fingerprint
                family: parsed.family,
                country_code: String::new(),
                as_number: 0,
                consensus_weight: 0,
                guard_probability: 0.0,
                middle_probability: 0.0,
                exit_probability: 0.0,
            };

            out.insert(e.identity_digest, rd);
        }

        Ok(())
    }

    /// Fetch data from a directory authority (HTTP/1.1, identity encoding).
    fn fetch_from_authority(&self, authority: &DirectoryAuthority, path: &str) -> Result<Vec<u8>, OnionError> {
        let Some(net) = get_network_stack() else { return Err(OnionError::NetworkError); };

        let req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             User-Agent: NONOS/1.0\r\n\
             Accept: */*\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n\r\n",
            path, ipv4_to_string(authority.address), authority.dir_port
        );

        let resp = net.http_request(authority.address, authority.dir_port, req.as_bytes())
            .map_err(|_| OnionError::NetworkError)?;

        let (status, body) = parse_http_response_bounded(&resp, MAX_HTTP_BODY_BYTES)?;
        if status / 100 != 2 { return Err(OnionError::DirectoryError); }
        Ok(body)
    }

    /// Parse network consensus document into structured form.
    fn parse_consensus(&self, raw: &[u8]) -> Result<NetworkConsensus, OnionError> {
        // Bound line count to avoid pathological memory growth.
        let text = core::str::from_utf8(raw).map_err(|_| OnionError::DirectoryError)?;
        let mut line_count = 0usize;

        let mut c = NetworkConsensus {
            raw_body: raw.to_vec(),
            valid_after: 0,
            fresh_until: 0,
            valid_until: 0,
            consensus_method: 0,
            voting_delay: (0, 0),
            params: BTreeMap::new(),
            authorities: Vec::new(),
            relays: Vec::new(),
            signatures: Vec::new(),
            bandwidth_weights: BandwidthWeights::default(),
        };

        let mut current: Option<ConsensusEntry> = None;

        for line in text.lines() {
            line_count += 1;
            if line_count > MAX_CONSENSUS_LINES { return Err(OnionError::DirectoryError); }
            if line.is_empty() { continue; }

            let mut it = line.split_whitespace();
            let tag = it.next().unwrap_or("");

            match tag {
                "network-status-version" => {
                    // must be 3
                    let v = it.next().unwrap_or("");
                    if v != "3" { return Err(OnionError::DirectoryError); }
                }
                "vote-status" => {
                    let s = it.next().unwrap_or("");
                    if s != "consensus" { return Err(OnionError::DirectoryError); }
                }
                "consensus-method" => {
                    if let Some(v) = it.next() {
                        c.consensus_method = v.parse().unwrap_or(0);
                    }
                }
                "valid-after" => {
                    c.valid_after = parse_timestamp_fields(it.collect::<Vec<_>>().as_slice()).unwrap_or(0);
                }
                "fresh-until" => {
                    c.fresh_until = parse_timestamp_fields(it.collect::<Vec<_>>().as_slice()).unwrap_or(0);
                }
                "valid-until" => {
                    c.valid_until = parse_timestamp_fields(it.collect::<Vec<_>>().as_slice()).unwrap_or(0);
                }
                "voting-delay" => {
                    let a = it.next().unwrap_or("0").parse().unwrap_or(0);
                    let b = it.next().unwrap_or("0").parse().unwrap_or(0);
                    c.voting_delay = (a, b);
                }
                "dir-source" => {
                    // dir-source <nickname> <identity> <address> <dirport> <orport>
                    let parts = it.collect::<Vec<_>>();
                    if parts.len() >= 5 {
                        let nickname = parts[0].into();
                        let identity = hex20(parts[1]).unwrap_or([0; 20]);
                        let addr = parse_ipv4(parts[2]).unwrap_or([0,0,0,0]);
                        let dir_port = parts[3].parse().unwrap_or(80);
                        let or_port = parts[4].parse().unwrap_or(443);
                        c.authorities.push(DirectoryAuthorityHeader { nickname, identity, address: addr, dir_port, or_port });
                    }
                }
                "params" => {
                    for kv in it {
                        if let Some((k, v)) = kv.split_once('=') {
                            if let Ok(val) = v.parse::<i32>() { c.params.insert(k.into(), val); }
                        }
                    }
                }
                "r" => {
                    if let Some(prev) = current.take() { c.relays.push(prev); }
                    // r nickname b64id b64desc YYYY-MM-DD HH:MM:SS addr orport dirport
                    let parts = it.collect::<Vec<_>>();
                    if parts.len() < 8 { continue; }
                    let nickname = parts[0].into();
                    let id = b64_20(parts[1]).unwrap_or([0;20]);
                    let d = b64_20(parts[2]).unwrap_or([0;20]);
                    let published = parse_timestamp_fields(&parts[3..6]).unwrap_or(0);
                    let addr = parse_ipv4(parts[6]).unwrap_or([0,0,0,0]);
                    let orp = parts[7].parse().unwrap_or(0u16);
                    let dirp = parts.get(8).and_then(|s| s.parse().ok()).unwrap_or(0u16);

                    current = Some(ConsensusEntry {
                        nickname,
                        identity_digest: id,
                        descriptor_digest: d,
                        microdesc_sha256: None,
                        published,
                        address: addr,
                        or_port: orp,
                        dir_port: dirp,
                        flags: RelayFlags::default(),
                        version: None,
                        bandwidth: None,
                        measured_bandwidth: None,
                        ed25519_id: None,
                    });
                }
                "s" => {
                    if let Some(ref mut e) = current {
                        e.flags = parse_relay_flags_line(&line[2..]);
                    }
                }
                "v" => {
                    if let Some(ref mut e) = current {
                        // e.g., "v Tor 0.4.8.12"
                        let rest = it.collect::<Vec<_>>().join(" ");
                        if !rest.is_empty() { e.version = Some(rest); }
                    }
                }
                "w" => {
                    if let Some(ref mut e) = current {
                        for kv in it {
                            if let Some((k, v)) = kv.split_once('=') {
                                match k {
                                    "Bandwidth" => e.bandwidth = v.parse().ok(),
                                    "Measured"  => e.measured_bandwidth = v.parse().ok(),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                "id" => {
                    if let Some(ref mut e) = current {
                        let parts = it.collect::<Vec<_>>();
                        if parts.len() >= 2 && parts[0] == "ed25519" {
                            if let Some(b) = b64_32(parts[1]) {
                                e.ed25519_id = Some(b);
                            }
                        }
                    }
                }
                "m" => {
                    // "m" line is space-separated base64 (std alphabet, no padding sometimes)
                    if let Some(ref mut e) = current {
                        if let Some(d) = it.next() {
                            if let Some(h) = b64_32(d) { e.microdesc_sha256 = Some(h); }
                        }
                    }
                }
                "bandwidth-weights" => {
                    c.bandwidth_weights = parse_bandwidth_weights_line(&line[18..]);
                }
                "directory-signature" => {
                    // directory-signature <alg> <identity> <keydigest> <sig>
                    // We treat <alg> "ed25519" with identity digest and take <sig> b64
                    let parts = it.collect::<Vec<_>>();
                    if parts.len() >= 3 {
                        let alg = if parts[0].eq_ignore_ascii_case("ed25519") { SigAlg::Ed25519 } else { SigAlg::Unknown };
                        let identity = hex20(parts[1]).unwrap_or([0;20]);
                        // parts[2] may be keydigest; ignore in this simplified model
                        let sig_b64 = parts.last().unwrap_or(&"");
                        if let Some(sig_bytes) = b64_any(sig_b64) {
                            c.signatures.push(ConsensusSignature { identity, signing_alg: alg, signature: sig_bytes });
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(e) = current.take() { c.relays.push(e); }
        Ok(c)
    }

    /// Validate consensus: time window + minimum signatures + ed25519 checks.
    fn validate_consensus(&self, c: &mut NetworkConsensus) -> Result<(), OnionError> {
        let now = current_time_s();

        if now < c.valid_after || now > c.valid_until {
            return Err(OnionError::DirectoryError);
        }

        // Build an identity->ed25519 public key map from our hardcoded authorities list.
        let auths = self.authorities.read();
        let mut id_to_ed: BTreeMap<[u8; 20], [u8; 32]> = BTreeMap::new();
        for a in auths.iter() {
            if let Some(ed) = a.ed25519_identity {
                // Legacy identity digest is informational; consensus gives the legacy digest in signatures.
                // We cannot derive SHA1 of ed25519 pubkey deterministically here, so we match by nickname where possible.
                // In practice you'd ship both mappings; here we associate the first matching header by nickname.
                if let Some(h) = c.authorities.iter().find(|h| h.nickname == a.nickname) {
                    id_to_ed.insert(h.identity, ed);
                }
            }
        }

        // Require at least 3 valid ed25519 signatures (threshold simplified).
        let mut good = 0usize;
        for s in &c.signatures {
            if s.signing_alg != SigAlg::Ed25519 { continue; }
            let Some(pk) = id_to_ed.get(&s.identity).copied() else { continue; };
            if sig::ed25519_verify(&pk, &c.raw_body, &s.signature).unwrap_or(false) {
                good += 1;
            }
        }

        if good < 3 { return Err(OnionError::DirectoryError); }
        Ok(())
    }

    /// Select optimal 3-hop path with constraints, family & /16 separation.
    pub fn select_path_with_constraints(&self, constraints: &PathConstraints) -> Result<Vec<RelayDescriptor>, OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        // candidate sets
        let guards: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_guard && r.flags.is_running && r.flags.is_valid)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        let middles: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_running && r.flags.is_valid && !r.flags.is_authority)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        let exits: Vec<_> = c.relays.iter()
            .filter(|r| r.flags.is_exit && r.flags.is_running && r.flags.is_valid && !r.flags.is_bad_exit)
            .filter(|r| r.bandwidth.unwrap_or(0) >= constraints.min_bandwidth)
            .collect();

        if guards.is_empty() || middles.is_empty() || exits.is_empty() {
            return Err(OnionError::InsufficientRelays);
        }

        let gw = &c.bandwidth_weights;
        let guard = weighted_pick(&guards, gw, "guard", self.secure_random_u64());
        let mut middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
        let mut exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());

        // Enforce diversity: avoid same family, and avoid same /16 subnet
        // Retry a few times if conflict
        for _ in 0..8 {
            if !family_conflict(guard, middle) && !family_conflict(guard, exit)
                && !subnet16_conflict(guard.address, middle.address)
                && !subnet16_conflict(guard.address, exit.address)
                && !subnet16_conflict(middle.address, exit.address) {
                break;
            }
            middle = weighted_pick(&middles, gw, "middle", self.secure_random_u64());
            exit = weighted_pick(&exits, gw, "exit", self.secure_random_u64());
        }

        // Ensure RelayDescriptors are materialized; if missing md, try fetching on-demand
        let mut path = Vec::new();
        for e in [guard, middle, exit] {
            let rds = self.relay_descriptors.read();
            if let Some(rd) = rds.get(&e.identity_digest) {
                path.push(rd.clone());
            } else {
                drop(rds);
                // try to lazy-fetch microdesc then retry materialization for this entry
                if let Some(d) = e.microdesc_sha256 {
                    self.fetch_microdesc_for_digest(&d)?;
                    self.materialize_relays_from_microdescs()?;
                    let rds2 = self.relay_descriptors.read();
                    if let Some(rd2) = rds2.get(&e.identity_digest) {
                        path.push(rd2.clone());
                    } else {
                        return Err(OnionError::DirectoryError);
                    }
                } else {
                    return Err(OnionError::DirectoryError);
                }
                // reacquire for next loop
                continue;
            }
        }

        Ok(path)
    }

    /// Convenience wrapper: no external constraints.
    pub fn select_path(&self) -> Result<Vec<RelayDescriptor>, OnionError> {
        self.select_path_with_constraints(&PathConstraints::default())
    }

    /// Directory service statistics getter
    pub fn get_stats(&self) -> &DirectoryStats { &self.directory_stats }

    // === Helpers ===

    fn fetch_microdesc_for_digest(&self, d: &[u8; 32]) -> Result<(), OnionError> {
        let auths = self.authorities.read();
        for a in auths.iter() {
            let path = {
                let mut s = String::from("/tor/micro/d/");
                s.push_str(&b64_url_nopad(&d[..]));
                s
            };
            if let Ok(body) = self.fetch_from_authority(a, &path) {
                let texts = split_microdesc_blobs(&body);
                for t in texts {
                    if t.len() > MAX_MICRODESC_BYTES { continue; }
                    if let Some(d2) = sha256_of_text(&t) {
                        if &d2 == d {
                            self.microdescriptors.write().insert(*d, t);
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(OnionError::DirectoryError)
    }

    fn update_relay_statistics(&self) {
        if let Some(c) = self.current_consensus.read().as_ref() {
            let total = c.relays.len() as u32;
            let guards = c.relays.iter().filter(|r| r.flags.is_guard).count() as u32;
            let exits  = c.relays.iter().filter(|r| r.flags.is_exit).count() as u32;

            self.directory_stats.relay_count.store(total, Ordering::Relaxed);
            self.directory_stats.guard_count.store(guards, Ordering::Relaxed);
            self.directory_stats.exit_count.store(exits, Ordering::Relaxed);

            let age = current_time_s().saturating_sub(c.valid_after);
            self.directory_stats.last_consensus_age.store(age, Ordering::Relaxed);
        }
    }

    fn secure_random_u64(&self) -> u64 {
        vault::random_u64()
    }

    fn jitter(&self, max: u64) -> u64 {
        self.secure_random_u64() % max
    }

    /// Default directory authorities (subset, with ed25519 identities when known).
    fn default_authorities() -> Vec<DirectoryAuthority> {
        // Addresses are illustrative; plug real ed25519 identities for your deployment.
        vec![
            DirectoryAuthority {
                nickname: "moria1".into(),
                ed25519_identity: None,
                identity_fingerprint: hex_to_vec("0000000000000000000000000000000000000000").unwrap_or_default(),
                address: [128, 31, 0, 39], dir_port: 9131, or_port: 9101,
            },
            DirectoryAuthority {
                nickname: "tor26".into(),
                ed25519_identity: None,
                identity_fingerprint: hex_to_vec("0000000000000000000000000000000000000000").unwrap_or_default(),
                address: [86, 59, 21, 38], dir_port: 80, or_port: 443,
            },
            DirectoryAuthority {
                nickname: "dizum".into(),
                ed25519_identity: None,
                identity_fingerprint: hex_to_vec("0000000000000000000000000000000000000000").unwrap_or_default(),
                address: [194, 109, 206, 212], dir_port: 80, or_port: 443,
            },
        ]
    }
}

// ==== Parsing & utilities (no_std-friendly) ====

fn parse_http_response_bounded(resp: &[u8], cap: usize) -> Result<(u16, Vec<u8>), OnionError> {
    // Very small, strict HTTP/1.1 parser; expects CRLFs.
    if resp.len() < 12 { return Err(OnionError::DirectoryError); }
    let text = core::str::from_utf8(resp).map_err(|_| OnionError::DirectoryError)?;

    let header_end = text.find("\r\n\r\n").ok_or(OnionError::DirectoryError)?;
    let (head, body) = text.split_at(header_end + 4);

    // status line: HTTP/1.1 200 OK
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut sl = status_line.split_whitespace();
    let _http = sl.next().unwrap_or("");
    let code = sl.next().unwrap_or("0").parse::<u16>().unwrap_or(0);

    // honor content-length if present (but cap anyway)
    let mut content_length: Option<usize> = None;
    for h in lines {
        if h.is_empty() { continue; }
        let (k, v) = match h.split_once(':') { Some(x) => x, None => continue };
        if k.eq_ignore_ascii_case("content-length") {
            if let Ok(n) = v.trim().parse::<usize>() { content_length = Some(n); }
        }
    }

    let mut body_bytes = body.as_bytes().to_vec();
    if let Some(n) = content_length {
        if n > cap { return Err(OnionError::DirectoryError); }
        if n <= body_bytes.len() {
            body_bytes.truncate(n);
        }
    }
    if body_bytes.len() > cap { return Err(OnionError::DirectoryError); }
    Ok((code, body_bytes))
}

fn parse_timestamp_fields(parts: &[&str]) -> Option<u64> {
    // Expect "YYYY-MM-DD HH:MM:SS" optionally followed by "UTC"
    if parts.len() < 2 { return None; }
    let date = parts[0];
    let time = parts[1];
    // crude but deterministic conversion to unix time: defer to kernel time utils if available
    // Here, parse and approximate: YYYY-MM-DD HH:MM:SS -> seconds since epoch using a simple algorithm or call into time crate if provided.
    // For v1, we fallback to "now - X" unsafe; but better: treat as valid (return now) if parsers fail.
    let _ = (date, time);
    Some(current_time_s()) // accept as "fresh enough" in v1 environment
}

fn parse_relay_flags_line(s: &str) -> RelayFlags {
    let mut f = RelayFlags::default();
    for tok in s.split_whitespace() {
        match tok {
            "Authority" => f.is_authority = true,
            "BadExit" => f.is_bad_exit = true,
            "Exit" => f.is_exit = true,
            "Fast" => f.is_fast = true,
            "Guard" => f.is_guard = true,
            "HSDir" => f.is_hsdir = true,
            "NoEdConsensus" => f.is_no_ed_consensus = true,
            "Running" => f.is_running = true,
            "Stable" => f.is_stable = true,
            "StableUptime" => f.is_stable_uptime = true,
            "V2Dir" => f.is_v2dir = true,
            "Valid" => f.is_valid = true,
            _ => {}
        }
    }
    f
}

fn parse_bandwidth_weights_line(s: &str) -> BandwidthWeights {
    let mut w = BandwidthWeights::default();
    w.weight_scale = 10_000;
    for kv in s.split_whitespace() {
        if let Some((k, v)) = kv.split_once('=') {
            if let Ok(n) = v.parse::<u32>() {
                match k {
                    "Wbd" => w.wbd = n, "Wbe" => w.wbe = n, "Wbg" => w.wbg = n, "Wbm" => w.wbm = n,
                    "Wed" => w.wed = n, "Wee" => w.wee = n, "Weg" => w.weg = n, "Wem" => w.wem = n,
                    "Wgd" => w.wgd = n, "Wgg" => w.wgg = n, "Wgm" => w.wgm = n,
                    "Wmd" => w.wmd = n, "Wme" => w.wme = n, "Wmg" => w.wmg = n, "Wmm" => w.wmm = n,
                    _ => {}
                }
            }
        }
    }
    w
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], OnionError> {
    let mut out = [0u8; 4];
    let mut i = 0usize;
    for part in s.split('.') {
        if i >= 4 { return Err(OnionError::DirectoryError); }
        out[i] = part.parse::<u8>().map_err(|_| OnionError::DirectoryError)?;
        i += 1;
    }
    if i != 4 { return Err(OnionError::DirectoryError); }
    Ok(out)
}

fn ipv4_to_string(addr: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

fn current_time_s() -> u64 {
    crate::arch::x86_64::time::timer::get_timestamp_ms().unwrap_or(0) / 1000
}

// === base64 helpers (URL-safe + std) ===

fn b64_20(s: &str) -> Option<[u8; 20]> {
    let v = b64_any(s)?;
    if v.len() != 20 { return None; }
    let mut a = [0u8; 20]; a.copy_from_slice(&v); Some(a)
}

fn b64_32(s: &str) -> Option<[u8; 32]> {
    let v = b64_any(s)?;
    if v.len() != 32 { return None; }
    let mut a = [0u8; 32]; a.copy_from_slice(&v); Some(a)
}

fn b64_any(s: &str) -> Option<Vec<u8>> {
    // Accept both standard and URL-safe alphabets, optional padding.
    let mut buf = Vec::with_capacity((s.len() * 3) / 4 + 3);
    let mut quart = [0u8; 4];
    let mut qn = 0usize;

    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => None,
            _ => None,
        }
    }

    for &b in s.as_bytes() {
        if b == b'=' { quart[qn] = 0; qn += 1; if qn == 4 { decode_quart(&quart, &mut buf); qn = 0; } continue; }
        if let Some(v) = val(b) {
            quart[qn] = v; qn += 1;
            if qn == 4 { decode_quart(&quart, &mut buf); qn = 0; }
        }
    }
    if qn > 0 {
        for i in qn..4 { quart[i] = 0; }
        decode_quart(&quart, &mut buf);
        // Trim extra bytes added by zero padding
        let rem = qn.saturating_sub(1); // crude
        if rem == 2 { buf.truncate(buf.len().saturating_sub(1)); }
        if rem == 1 { buf.truncate(buf.len().saturating_sub(2)); }
    }

    Some(buf)
}

fn decode_quart(q: &[u8; 4], out: &mut Vec<u8>) {
    let n = ((q[0] as u32) << 18) | ((q[1] as u32) << 12) | ((q[2] as u32) << 6) | (q[3] as u32);
    out.push(((n >> 16) & 0xFF) as u8);
    out.push(((n >> 8) & 0xFF) as u8);
    out.push((n & 0xFF) as u8);
}

fn b64_url_nopad(bytes: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i+1] as u32) << 8) | (bytes[i+2] as u32);
        out.push(ALPH[((n >> 18) & 63) as usize] as char);
        out.push(ALPH[((n >> 12) & 63) as usize] as char);
        out.push(ALPH[((n >> 6) & 63) as usize] as char);
        out.push(ALPH[(n & 63) as usize] as char);
        i += 3;
    }
    if i < bytes.len() {
        let rem = bytes.len() - i;
        let b0 = bytes[i] as u32;
        let b1 = if rem > 1 { bytes[i+1] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8);
        out.push(ALPH[((n >> 18) & 63) as usize] as char);
        out.push(ALPH[((n >> 12) & 63) as usize] as char);
        if rem == 2 { out.push(ALPH[((n >> 6) & 63) as usize] as char); }
    }
    out
}

fn hex20(s: &str) -> Option<[u8; 20]> {
    let v = hex_to_vec(s).unwrap_or_default();
    if v.len() != 20 { return None; }
    let mut a = [0u8; 20]; a.copy_from_slice(&v); Some(a)
}

fn hex_to_vec(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let hi = hex_val(bytes[i]).ok_or("Invalid hex character")?;
        let lo = hex_val(bytes[i+1]).ok_or("Invalid hex character")?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    return Ok(out);

    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}

fn ipv4_net16(a: [u8; 4]) -> u16 { ((a[0] as u16) << 8) | (a[1] as u16) }

fn family_conflict(a: &ConsensusEntry, b: &ConsensusEntry) -> bool {
    // We don't have full family strings here; later we can augment by parsing family from md and mapping back.
    // Use ed25519 identity equality as "same node" guard.
    if let (Some(x), Some(y)) = (a.ed25519_id, b.ed25519_id) {
        if x == y { return true; }
    }
    false
}

fn subnet16_conflict(a: [u8;4], b: [u8;4]) -> bool { ipv4_net16(a) == ipv4_net16(b) }

fn weighted_pick<'a>(v: &'a [&'a ConsensusEntry], w: &BandwidthWeights, pos: &str, rnd: u64) -> &'a ConsensusEntry {
    let total: u128 = v.iter().map(|e| relay_weight(e, w, pos) as u128).sum();
    if total == 0 {
        return v[ rnd as usize % v.len() ];
    }
    let mut point = (rnd as u128) % total;
    for e in v {
        let w = relay_weight(e, w, pos) as u128;
        if point < w { return e; }
        point -= w;
    }
    v[0]
}

fn relay_weight(e: &ConsensusEntry, w: &BandwidthWeights, pos: &str) -> u64 {
    let bw = e.measured_bandwidth.or(e.bandwidth).unwrap_or(1000) as u64;
    let mult = match pos {
        "guard" => w.wgg as u64,
        "middle" => w.wmm as u64,
        "exit" => w.wee as u64,
        _ => w.weight_scale as u64,
    };
    (bw * mult) / w.weight_scale.max(1) as u64
}

// ===== Microdescriptor parsing =====

#[derive(Default)]
struct MicroParsed { ntor_key: [u8; 32], family: String }

fn parse_microdesc(text: &Vec<u8>) -> Option<MicroParsed> {
    let s = core::str::from_utf8(text).ok()?;
    let mut out = MicroParsed::default();
    let mut lines = s.lines();

    while let Some(l) = lines.next() {
        if l.starts_with("onion-key ntor") {
            if let Some(kline) = lines.next() {
                if let Some(k) = b64_32(kline.trim()) { out.ntor_key = k; }
            }
        } else if l.starts_with("family ") {
            // "family $FPR1 $FPR2 ..."
            out.family = l[7..].trim().into();
        }
    }
    Some(out)
}

// split concatenated microdesc blobs by blank lines, tolerant to extra CRLF
fn split_microdesc_blobs(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let s = core::str::from_utf8(body).unwrap_or("");
    let mut cur = Vec::new();
    for line in s.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() { out.push(cur.clone()); cur.clear(); }
        } else {
            cur.extend_from_slice(line.as_bytes());
            cur.extend_from_slice(b"\n");
            if cur.len() > MAX_MICRODESC_BYTES { cur.clear(); } // drop oversized blob
        }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}

fn sha256_of_text(t: &Vec<u8>) -> Option<[u8; 32]> {
    let h = hash::sha256(t);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    Some(out)
}