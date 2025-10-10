#![no_std]

/*!
 Network Interface for Tor Onion Routing

 Networking implementation that integrates with NONOS:
 - TCP socket operations with proper error handling
 - IPv4/IPv6 address resolution and routing
 - TLS layer integration via a pluggable TlsProvider (SNI/ALPN/min TLS ver)
 - Network buffer management with timeouts
 - Connection pooling with TTL and health gating
 - Global + per-connection bandwidth limiting (token buckets, up/down)
 - Backpressure-friendly I/O helpers
*/

use crate::network::onion::relay::TcpSocketExt;
use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::cmp::min;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once};

use super::OnionError;
use crate::network::{tcp::TcpSocket, IpAddress};

/* ===== TLS integration ===== */

/// External TLS provider hooked up by the platform TLS stack.
pub trait TlsProvider: Sync + Send {
    /// Perform a full TLS handshake over the given socket with options.
    /// Must leave the socket ready for application data on success.
    fn handshake_with_opts(
        &self,
        sock: &TcpSocket,
        sni: Option<&'static str>,
        alpn: Option<&'static [&'static str]>,
        min_tls_version: u16, // e.g., 0x0304 for TLS 1.3
    ) -> Result<TlsSessionInfo, OnionError>;
}

/// TLS session info returned by the provider.
#[derive(Debug, Clone)]
pub struct TlsSessionInfo {
    pub cipher_suite: u16,
    pub protocol_version: u16, // 0x0304 = TLS 1.3
    pub traffic_secret_len: u16,
}

/* ===== Dial options ===== */

#[derive(Clone, Copy)]
pub struct DialOptions {
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    /// Per-connection upstream limit (bytes/sec). 0 = inherit manager global.
    pub bandwidth_up_bps: u64,
    /// Per-connection downstream limit (bytes/sec). 0 = inherit manager global.
    pub bandwidth_down_bps: u64,
    /// Prefer IPv6 when both are available (placeholder for future dual-stack).
    pub prefer_ipv6: bool,
    /// Race window for Happy Eyeballs (kept for future use).
    pub happy_eyeballs_ms: u64,
    /// Optional SNI for TLS.
    pub sni: Option<&'static str>,
    /// Optional ALPN list for TLS.
    pub alpn: Option<&'static [&'static str]>,
    /// Minimum TLS version (0x0304 = TLS1.3).
    pub min_tls_version: u16,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            read_timeout_ms: 15_000,
            write_timeout_ms: 15_000,
            bandwidth_up_bps: 0,
            bandwidth_down_bps: 0,
            prefer_ipv6: true,
            happy_eyeballs_ms: 250,
            sni: None,
            alpn: None,
            min_tls_version: 0x0304,
        }
    }
}

/* ===== Manager & connection types ===== */

/// Real network manager for Tor operations
pub struct TorNetworkManager {
    active: Mutex<BTreeMap<u32, TorConnection>>,
    next_id: AtomicU32,
    stats: NetworkStats,
    pool: ConnectionPool,
    tls: &'static dyn TlsProvider,
    /// Default per-op timeout used by helpers when not overridden (ms).
    io_timeout_ms: u64,
    /// Global bandwidth limiter (bytes/sec).
    limiter: Mutex<TokenBucket>,
}

/// Tor network connection with real TCP backing
pub struct TorConnection {
    pub id: u32,
    pub socket: TcpSocket,
    pub remote_addr: IpAddress,
    pub remote_port: u16,
    pub local_port: u16,
    pub state: ConnectionState,
    pub created_at_ms: u64,
    pub last_activity_ms: u64,
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub tls: Option<TlsConnectionState>,
    pub updown: Option<DirectionLimiters>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    TlsHandshake,
    Authenticated,
    Closing,
    Closed,
    Error,
}

#[derive(Debug, Clone)]
pub struct TlsConnectionState {
    pub handshake_complete: bool,
    pub cipher_suite: Option<u16>,
    pub protocol_version: u16,
    pub traffic_secret_len: u16,
}

/// Network statistics and monitoring
#[derive(Debug)]
pub struct NetworkStats {
    pub total_connections: AtomicU32,
    pub active_connections: AtomicU32,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub connection_failures: AtomicU32,
    pub bandwidth_limit_bytes_per_sec: AtomicU64,
}

/// Connection pool for reusing TCP/TLS connections
pub struct ConnectionPool {
    // (addr, port) -> stack of idle connections (most-recent last)
    buckets: Mutex<BTreeMap<(IpAddress, u16), Vec<TorConnection>>>,
    max_pool_size: usize,
    max_idle_ms: u64,
}

/* ===== Bandwidth limiting (token buckets) ===== */

#[derive(Debug)]
struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_per_ms: u64,
    last_refill_ms: u64,
}

impl TokenBucket {
    fn new(bytes_per_sec: u64, now_ms: u64) -> Self {
        let cap = if bytes_per_sec == 0 { 1 } else { bytes_per_sec }; // avoid div by zero
        let per_ms = core::cmp::max(1, cap / 1000);
        Self { capacity: cap, tokens: cap, refill_per_ms: per_ms, last_refill_ms: now_ms }
    }

    fn set_rate(&mut self, bytes_per_sec: u64, now_ms: u64) {
        self.refill(now_ms);
        self.capacity = if bytes_per_sec == 0 { 1 } else { bytes_per_sec };
        self.tokens = core::cmp::min(self.tokens, self.capacity);
        self.refill_per_ms = core::cmp::max(1, self.capacity / 1000);
    }

    fn refill(&mut self, now_ms: u64) {
        if now_ms <= self.last_refill_ms {
            return;
        }
        let delta = now_ms - self.last_refill_ms;
        let add = delta.saturating_mul(self.refill_per_ms);
        self.tokens = core::cmp::min(self.capacity, self.tokens.saturating_add(add));
        self.last_refill_ms = now_ms;
    }

    fn try_consume(&mut self, n: u64, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
struct DirectionLimiters {
    up: TokenBucket,
    down: TokenBucket,
}

/* ===== Connection stats snapshot ===== */

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub connection_id: u32,
    pub remote_addr: IpAddress,
    pub remote_port: u16,
    pub state: ConnectionState,
    pub uptime_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_activity_ms: u64,
}

/* ===== Global singleton ===== */

static TOR_NETWORK_MANAGER: Once<TorNetworkManager> = Once::new();

/// Initialize global Tor network manager.
/// `tls` is the concrete TLS provider.
/// `bandwidth_limit_bps` is global byte/sec cap (0 => 1 MiB/s).
pub fn init_tor_network(tls: &'static dyn TlsProvider, bandwidth_limit_bps: u64) {
    let now = timestamp_ms();
    TOR_NETWORK_MANAGER.call_once(|| TorNetworkManager {
        active: Mutex::new(BTreeMap::new()),
        next_id: AtomicU32::new(1),
        stats: NetworkStats {
            total_connections: AtomicU32::new(0),
            active_connections: AtomicU32::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connection_failures: AtomicU32::new(0),
            bandwidth_limit_bytes_per_sec: AtomicU64::new(if bandwidth_limit_bps == 0 {
                1_048_576
            } else {
                bandwidth_limit_bps
            }),
        },
        pool: ConnectionPool {
            buckets: Mutex::new(BTreeMap::new()),
            max_pool_size: 32,
            max_idle_ms: 300_000, // 5 minutes
        },
        tls,
        io_timeout_ms: 15_000,
        limiter: Mutex::new(TokenBucket::new(
            if bandwidth_limit_bps == 0 { 1_048_576 } else { bandwidth_limit_bps },
            now,
        )),
    });
}

/// Get global Tor network manager
pub fn get_tor_network() -> &'static TorNetworkManager {
    TOR_NETWORK_MANAGER.get().expect("Tor network manager not initialized")
}

/* ===== Public API ===== */

impl TorNetworkManager {
    /// Create or reuse a TCP connection to a Tor relay (simple API).
    pub fn connect_to_relay(&self, addr: IpAddress, port: u16) -> Result<u32, OnionError> {
        self.connect_to_relay_ex(addr, port, DialOptions::default())
    }

    /// Create or reuse a TCP connection with options
    /// (bandwidth/timeouts/SNI/ALPN).
    pub fn connect_to_relay_ex(
        &self,
        addr: IpAddress,
        port: u16,
        opts: DialOptions,
    ) -> Result<u32, OnionError> {
        // Try pool first
        if let Some(mut pooled) = self.pool.take(&addr, port, timestamp_ms()) {
            // Refresh per-conn limiters if defined by options
            if pooled.updown.is_none() && (opts.bandwidth_up_bps | opts.bandwidth_down_bps) != 0 {
                let now = timestamp_ms();
                let global = self.stats.bandwidth_limit_bytes_per_sec.load(Ordering::SeqCst);
                let up = if opts.bandwidth_up_bps == 0 { global } else { opts.bandwidth_up_bps };
                let down =
                    if opts.bandwidth_down_bps == 0 { global } else { opts.bandwidth_down_bps };
                pooled.updown = Some(DirectionLimiters {
                    up: TokenBucket::new(up, now),
                    down: TokenBucket::new(down, now),
                });
            }
            pooled.last_activity_ms = timestamp_ms();
            let id = pooled.id;
            self.active.lock().insert(id, pooled);
            self.stats.active_connections.fetch_add(1, Ordering::SeqCst);
            return Ok(id);
        }

        // Fresh connect (placeholder for full Happy Eyeballs when we have
        // hostnames/multi-addrs)
        let (sock, local_port) = self.direct_connect(addr, port, opts.connect_timeout_ms)?;

        let mut conn = TorConnection {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            socket: sock,
            remote_addr: addr,
            remote_port: port,
            local_port,
            state: ConnectionState::Connected,
            created_at_ms: timestamp_ms(),
            last_activity_ms: timestamp_ms(),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            tls: None,
            updown: None,
        };

        if (opts.bandwidth_up_bps | opts.bandwidth_down_bps) != 0 {
            let now = timestamp_ms();
            let global = self.stats.bandwidth_limit_bytes_per_sec.load(Ordering::SeqCst);
            let up = if opts.bandwidth_up_bps == 0 { global } else { opts.bandwidth_up_bps };
            let down = if opts.bandwidth_down_bps == 0 { global } else { opts.bandwidth_down_bps };
            conn.updown = Some(DirectionLimiters {
                up: TokenBucket::new(up, now),
                down: TokenBucket::new(down, now),
            });
        }

        let id = conn.id;
        self.active.lock().insert(id, conn);
        self.stats.total_connections.fetch_add(1, Ordering::SeqCst);
        self.stats.active_connections.fetch_add(1, Ordering::SeqCst);
        Ok(id)
    }

    /// Perform a TLS handshake using the configured TlsProvider and supplied
    /// options.
    pub fn perform_tls_handshake_ex(
        &self,
        id: u32,
        sni: Option<&'static str>,
        alpn: Option<&'static [&'static str]>,
        min_tls_version: u16,
    ) -> Result<(), OnionError> {
        let mut map = self.active.lock();
        let conn = map.get_mut(&id).ok_or(OnionError::NetworkError)?;

        if conn.state != ConnectionState::Connected {
            return Err(OnionError::NetworkError);
        }

        conn.state = ConnectionState::TlsHandshake;
        let session = self.tls.handshake_with_opts(&conn.socket, sni, alpn, min_tls_version)?;
        conn.tls = Some(TlsConnectionState {
            handshake_complete: true,
            cipher_suite: Some(session.cipher_suite),
            protocol_version: session.protocol_version,
            traffic_secret_len: session.traffic_secret_len,
        });
        conn.state = ConnectionState::Authenticated;
        conn.last_activity_ms = timestamp_ms();
        Ok(())
    }

    /// Convenience TLS handshake using defaults.
    pub fn perform_tls_handshake(&self, id: u32) -> Result<(), OnionError> {
        self.perform_tls_handshake_ex(id, None, None, 0x0304)
    }

    /// Send application data (obeys global + per-conn limits). Returns bytes
    /// written.
    pub fn send_data(&self, id: u32, buf: &[u8]) -> Result<usize, OnionError> {
        if buf.is_empty() {
            return Ok(0);
        }

        let now = timestamp_ms();
        // global limiter gate
        {
            let mut limiter = self.limiter.lock();
            if !limiter.try_consume(buf.len() as u64, now) {
                return Err(OnionError::RateLimited);
            }
        }

        let timeout = self.io_timeout_ms;
        let mut map = self.active.lock();
        let conn = map.get_mut(&id).ok_or(OnionError::NetworkError)?;
        if conn.state != ConnectionState::Connected && conn.state != ConnectionState::Authenticated
        {
            return Err(OnionError::NetworkError);
        }

        // per-conn UP limiter
        if let Some(lims) = conn.updown.as_mut() {
            if !lims.up.try_consume(buf.len() as u64, now) {
                return Err(OnionError::RateLimited);
            }
        }

        let n = self.tcp_write_all(&conn.socket, buf, timeout)?;
        conn.bytes_sent.fetch_add(n as u64, Ordering::SeqCst);
        conn.last_activity_ms = timestamp_ms();
        self.stats.bytes_sent.fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }

    /// Receive some data into `dst`. Returns bytes read (0 means graceful EOF).
    pub fn receive_data(&self, id: u32, dst: &mut [u8]) -> Result<usize, OnionError> {
        if dst.is_empty() {
            return Ok(0);
        }
        let timeout = self.io_timeout_ms;
        let mut map = self.active.lock();
        let conn = map.get_mut(&id).ok_or(OnionError::NetworkError)?;
        if conn.state != ConnectionState::Connected && conn.state != ConnectionState::Authenticated
        {
            return Err(OnionError::NetworkError);
        }

        let n = self.tcp_read_some(&conn.socket, dst, timeout)?;
        if n > 0 {
            // per-conn DOWN limiter
            if let Some(lims) = conn.updown.as_mut() {
                let now = timestamp_ms();
                if !lims.down.try_consume(n as u64, now) {
                    // do not roll back the read, but surface rate-limit
                    return Err(OnionError::RateLimited);
                }
            }
            conn.bytes_recv.fetch_add(n as u64, Ordering::SeqCst);
            conn.last_activity_ms = timestamp_ms();
            self.stats.bytes_received.fetch_add(n as u64, Ordering::SeqCst);
        }
        Ok(n)
    }

    /// Close connection and return to pool if eligible; else hard-close.
    pub fn close_connection(&self, id: u32) -> Result<(), OnionError> {
        let mut map = self.active.lock();
        let mut conn = map.remove(&id).ok_or(OnionError::NetworkError)?;
        conn.state = ConnectionState::Closing;

        let now = timestamp_ms();
        let pooled = self.can_pool(&conn);
        if pooled {
            conn.last_activity_ms = now;
            self.pool.put(conn);
        } else {
            let _ = self.tcp_close(&conn.socket);
        }

        self.stats.active_connections.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }

    /// Resolve hostname to IP address via system DNS (A/AAAA).
    pub fn resolve_hostname(&self, hostname: &str) -> Result<IpAddress, OnionError> {
        let ips = crate::network::dns::resolve(hostname).map_err(|_| OnionError::NetworkError)?;
        ips.into_iter().next().map(|ip| IpAddress::V4(ip)).ok_or(OnionError::NetworkError)
    }

    /// Get per-connection stats snapshot.
    pub fn get_connection_stats(&self, id: u32) -> Option<ConnectionStats> {
        let map = self.active.lock();
        map.get(&id).map(|c| ConnectionStats {
            connection_id: c.id,
            remote_addr: c.remote_addr,
            remote_port: c.remote_port,
            state: c.state,
            uptime_ms: timestamp_ms().saturating_sub(c.created_at_ms),
            bytes_sent: c.bytes_sent.load(Ordering::SeqCst),
            bytes_received: c.bytes_recv.load(Ordering::SeqCst),
            last_activity_ms: timestamp_ms().saturating_sub(c.last_activity_ms),
        })
    }

    /// Get global stats (direct reference to atoms; safe to read).
    pub fn get_network_stats(&self) -> &NetworkStats {
        &self.stats
    }

    /// Update global bandwidth limit (bytes/sec).
    pub fn set_bandwidth_limit(&self, bytes_per_sec: u64) {
        self.stats.bandwidth_limit_bytes_per_sec.store(bytes_per_sec, Ordering::SeqCst);
        let now = timestamp_ms();
        let mut tb = self.limiter.lock();
        tb.set_rate(bytes_per_sec, now);
    }

    /// Sweep idle/errored/closed connections from active map; also evicts
    /// expired pooled conns.
    pub fn cleanup(&self) {
        let now = timestamp_ms();
        // Active map cleanup
        {
            let mut map = self.active.lock();
            let to_drop: Vec<u32> = map
                .iter()
                .filter(|(_, c)| {
                    (now.saturating_sub(c.last_activity_ms) > 300_000)
                        || (matches!(c.state, ConnectionState::Error | ConnectionState::Closed))
                })
                .map(|(id, _)| *id)
                .collect();

            for id in to_drop {
                if let Some(conn) = map.remove(&id) {
                    let _ = self.tcp_close(&conn.socket);
                    self.stats.active_connections.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }
        // Pool cleanup
        self.pool.evict_idle(now);
    }

    /* ===== Private helpers ===== */

    /// Direct single-address connect (placeholder for future dual-stack
    /// racing).
    fn direct_connect(
        &self,
        addr: IpAddress,
        port: u16,
        connect_timeout_ms: u64,
    ) -> Result<(TcpSocket, u16), OnionError> {
        let socket = TcpSocket::new();
        let start = timestamp_ms();
        if let Some(net) = crate::network::get_network_stack() {
            while timestamp_ms().saturating_sub(start) <= connect_timeout_ms {
                let ipv4_addr = match addr {
                    crate::network::ip::IpAddress::V4(addr) => addr,
                    crate::network::ip::IpAddress::V6(_) => return Err(OnionError::NetworkError),
                };
                match net.tcp_connect(&socket, ipv4_addr, port) {
                    Ok(()) => {
                        let lp = net.get_local_port(&socket).unwrap_or(0);
                        return Ok((socket, lp));
                    }
                    Err(_) => {
                        // brief yield and retry until timeout
                        crate::time::yield_now();
                    }
                }
            }
            self.stats.connection_failures.fetch_add(1, Ordering::SeqCst);
            Err(OnionError::Timeout)
        } else {
            Err(OnionError::NetworkError)
        }
    }

    fn tcp_write_all(
        &self,
        socket: &TcpSocket,
        mut buf: &[u8],
        timeout_ms: u64,
    ) -> Result<usize, OnionError> {
        let mut written = 0usize;
        let start = timestamp_ms();
        if let Some(net) = crate::network::get_network_stack() {
            while !buf.is_empty() {
                if timestamp_ms().saturating_sub(start) > timeout_ms {
                    return Err(OnionError::Timeout);
                }
                match net.tcp_send(socket.connection_id(), buf) {
                    Ok(n) if n > 0 => {
                        written += n;
                        buf = &buf[n..];
                    }
                    Ok(_) => {
                        // nothing written; yield and retry until timeout
                        crate::time::yield_now();
                    }
                    Err(_) => return Err(OnionError::NetworkError),
                }
            }
            Ok(written)
        } else {
            Err(OnionError::NetworkError)
        }
    }

    fn tcp_read_some(
        &self,
        socket: &TcpSocket,
        dst: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, OnionError> {
        let start = timestamp_ms();
        if let Some(net) = crate::network::get_network_stack() {
            loop {
                if timestamp_ms().saturating_sub(start) > timeout_ms {
                    return Err(OnionError::Timeout);
                }
                match net.tcp_receive(socket.connection_id(), dst.len()) {
                    Ok(data) => {
                        let n = min(dst.len(), data.len());
                        if n == 0 {
                            // 0-length read -> maybe no data; check closure
                            if net.tcp_is_closed(socket.connection_id()).unwrap_or(false) {
                                return Ok(0);
                            }
                            crate::time::yield_now();
                            continue;
                        }
                        dst[..n].copy_from_slice(&data[..n]);
                        return Ok(n);
                    }
                    Err(_) => {
                        // transient? retry until timeout
                        crate::time::yield_now();
                    }
                }
            }
        } else {
            Err(OnionError::NetworkError)
        }
    }

    fn tcp_close(&self, socket: &TcpSocket) -> Result<(), OnionError> {
        if let Some(net) = crate::network::get_network_stack() {
            net.tcp_close(socket.connection_id()).map_err(|_| OnionError::NetworkError)
        } else {
            Err(OnionError::NetworkError)
        }
    }

    fn can_pool(&self, c: &TorConnection) -> bool {
        matches!(c.state, ConnectionState::Authenticated)
            && c.tls.as_ref().map_or(false, |t| t.handshake_complete)
    }
}

/* ===== Pool impl ===== */

impl ConnectionPool {
    fn take(&self, addr: &IpAddress, port: u16, now_ms: u64) -> Option<TorConnection> {
        let mut buckets = self.buckets.lock();
        if let Some(vec) = buckets.get_mut(&(*addr, port)) {
            while let Some(mut c) = vec.pop() {
                if now_ms.saturating_sub(c.last_activity_ms) > self.max_idle_ms
                    || matches!(c.state, ConnectionState::Closed | ConnectionState::Error)
                {
                    // stale/closed -> drop
                    continue;
                }
                return Some(c);
            }
        }
        None
    }

    fn put(&self, conn: TorConnection) {
        if !matches!(conn.state, ConnectionState::Authenticated) {
            return;
        }
        let key = (conn.remote_addr, conn.remote_port);
        let mut buckets = self.buckets.lock();
        let entry = buckets.entry(key).or_insert_with(Vec::new);
        if entry.len() < self.max_pool_size {
            entry.push(conn);
        }
        // else: silently drop (caller already removed from active; kernel may
        // close on drop)
    }

    fn evict_idle(&self, now_ms: u64) {
        let mut buckets = self.buckets.lock();
        let keys: Vec<(IpAddress, u16)> = buckets.keys().copied().collect();
        for k in keys {
            if let Some(v) = buckets.get_mut(&k) {
                v.retain(|c| {
                    (now_ms.saturating_sub(c.last_activity_ms) <= self.max_idle_ms)
                        && !matches!(c.state, ConnectionState::Closed | ConnectionState::Error)
                });
            }
        }
    }
}

/* ===== Utilities ===== */

#[inline]
fn timestamp_ms() -> u64 {
    crate::time::timestamp_millis()
}
