//! NONOS Base Network Stack 

#![no_std]

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::cmp::min;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::{Mutex, Once};

// Real smoltcp integration
use smoltcp::{
    iface::{Interface, SocketSet, Routes, Config as IfaceConfig},
    phy::{ChecksumCapabilities, DeviceCapabilities, Medium, RxToken, TxToken, Device},
    socket::{tcp, udp},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{EthernetAddress, HardwareAddress, IpAddress as SmolIpAddress, IpCidr, Ipv4Address as SmolIpv4Address, Ipv6Address as SmolIpv6Address},
};

pub type SmolHandle = smoltcp::iface::SocketHandle;
pub type Ipv4Address = [u8; 4];
pub type Ipv4Cidr = ();
pub type Ipv4Gateway = ();
pub type Ipv6Address = [u8; 16];

pub use super::ip::IpAddress;

/// Public TcpSocket wrapper used by callers.
#[derive(Debug, Clone)]
pub struct TcpSocket {
    id: u32,
    pub remote_port: u16,
}
impl TcpSocket {
    pub fn new() -> Self {
        Self { id: NEXT_ID.fetch_add(1, Ordering::SeqCst), remote_port: 0 }
    }
    pub fn connection_id(&self) -> u32 { self.id }
    pub fn from_connection(id: u32) -> Self { Self { id, remote_port: 0 } }
}

/// Legacy "Socket" shim type used in onion/relay.rs
#[derive(Debug, Clone)]
pub struct Socket {
    conn_id: Option<u32>,
}
impl Socket {
    pub fn new() -> Self { Self { conn_id: None } }
    pub fn for_connection(id: u32) -> Self { Self { conn_id: Some(id) } }
    pub fn connection_id(&self) -> Option<u32> { self.conn_id }
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Default, Clone)]
pub struct NetworkStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

struct ConnectionEntry {
    id: u32,
    tcp: SmolHandle,
    last_activity_ms: u64,
    closed: bool,
}

pub struct NetworkStack {
    iface: Mutex<Interface>,
    sockets: Mutex<SocketSet<'static>>,
    routes: Mutex<Routes>,
    conns: Mutex<BTreeMap<u32, ConnectionEntry>>,
    next_id: AtomicU32,
    stats: Mutex<NetworkStats>,
    default_dns_v4: Mutex<Ipv4Address>,
}

static STACK: Once<NetworkStack> = Once::new();

pub fn init_network_stack() {
    STACK.call_once(|| {
        let mut dev = SmolDeviceAdapter;

        // Interface configuration
        let mut cfg = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(DEFAULT_MAC)));
        cfg.random_seed = 0xD1E5_7A2C;
        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(now_ms() as i64));

        // Default addresses: loopback v4 and v6
        let _ = iface.update_ip_addrs(|ips| {
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv4(SmolIpv4Address::new(127, 0, 0, 1)), 8));
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK), 128));
        });

        let routes = Routes::new();
        let sockets = SocketSet::new(vec![]);

        NetworkStack {
            iface: Mutex::new(iface),
            sockets: Mutex::new(sockets),
            routes: Mutex::new(routes),
            conns: Mutex::new(BTreeMap::new()),
            next_id: AtomicU32::new(1),
            stats: Mutex::new(NetworkStats::default()),
            default_dns_v4: Mutex::new([1, 1, 1, 1]), // Cloudflare default
        }
    });
}

pub fn get_network_stack() -> Option<&'static NetworkStack> {
    STACK.get()
}

/* ===== Device adapter ===== */

pub trait SmolDevice: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
    fn recv(&self) -> Option<Vec<u8>>; // a full Ethernet frame
    fn transmit(&self, frame: &[u8]) -> Result<(), ()>;
    fn mac(&self) -> [u8; 6];
    fn link_mtu(&self) -> usize { 1500 }
}

static DEVICE_SLOT: Once<&'static dyn SmolDevice> = Once::new();
const DEFAULT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

pub fn register_device(dev: &'static dyn SmolDevice) {
    DEVICE_SLOT.call_once(|| dev);
    if let Some(stack) = get_network_stack() {
        let mac = dev.mac();
        let mut iface = stack.iface.lock();
        iface.set_hardware_addr(HardwareAddress::Ethernet(EthernetAddress(mac)));
    }
}

fn now_ms() -> u64 {
    if let Some(dev) = DEVICE_SLOT.get() {
        return dev.now_ms();
    }
    crate::time::timestamp_millis()
}

// smoltcp device adapter

pub struct SmolDeviceAdapter;

impl Device for SmolDeviceAdapter {
    type RxToken<'a> = RxT;
    type TxToken<'a> = TxT;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = DEVICE_SLOT.get().map(|d| d.link_mtu()).unwrap_or(1500);
        caps.medium = Medium::Ethernet;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(dev) = DEVICE_SLOT.get() {
            if let Some(frame) = dev.recv() {
                return Some((RxT(frame), TxT));
            }
        }
        None
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxT)
    }
}

pub struct RxT(Vec<u8>);
impl RxToken for RxT {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.0;
        f(&mut buf)
    }
}

pub struct TxT;
impl TxToken for TxT {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut out = vec![0u8; len];
        let res = f(&mut out);
        if let Some(dev) = DEVICE_SLOT.get() {
            let _ = dev.transmit(&out);
        }
        res
    }
}

/* ===== Interface helpers ===== */

impl NetworkStack {
    pub fn set_ipv4_config(&self, ip: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>) {
        let mut iface = self.iface.lock();
        let _ = iface.update_ip_addrs(|ips| {
            ips.clear();
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv4(SmolIpv4Address::from_bytes(&ip)), prefix));
            let _ = ips.push(IpCidr::new(SmolIpAddress::Ipv6(SmolIpv6Address::LOOPBACK), 128));
        });
        if let Some(gw) = gateway {
            let mut routes = self.routes.lock();
            let gw_addr = SmolIpv4Address::from_bytes(&gw);
            routes.add_default_ipv4_route(gw_addr).ok();
            drop(routes);
            // Routes are managed by the interface internally
        }
    }

    #[inline]
    fn poll(&self) {
        let ts = SmolInstant::from_millis(now_ms() as i64);
        let mut iface = self.iface.lock();
        let mut sockets = self.sockets.lock();
        let _ = iface.poll(ts, &mut SmolDeviceAdapter, &mut *sockets);
    }

    fn pick_single_active_conn(&self) -> Option<u32> {
        let conns = self.conns.lock();
        let mut last: Option<u32> = None;
        for (id, c) in conns.iter() {
            if !c.closed {
                last = Some(*id);
            }
        }
        // Only return if exactly one
        if conns.iter().filter(|(_, c)| !c.closed).count() == 1 {
            last
        } else {
            None
        }
    }
}

/* ===== TCP server/listener for relay.rs ===== */

impl NetworkStack {
    pub fn bind_tcp_port(&self, port: u16) -> Result<(), &'static str> {
        let mut sockets = self.sockets.lock();
        let rx = tcp::SocketBuffer::new(vec![0; 8192]);
        let tx = tcp::SocketBuffer::new(vec![0; 8192]);
        let mut s = tcp::Socket::new(rx, tx);
        s.listen(port).map_err(|_| "listen failed")?;
        let _handle = sockets.add(s);
        Ok(())
    }

    pub fn listen_tcp(&self, _backlog: usize) -> Result<(), &'static str> {
        // smoltcp does not use backlog; kept for API parity
        Ok(())
    }

    pub fn accept_tcp_connection(&self) -> Result<u32, &'static str> {
        // Walk sockets to find a listening socket with an established endpoint.
        // smoltcp models a single tcp::Socket per connection; emulate accept by picking the first active listener.
        let mut sockets = self.sockets.lock();
        let now = now_ms();
        let handles: Vec<_> = sockets.iter().map(|h| h.0).collect();
        for h in handles {
            let sock = sockets.get::<tcp::Socket>(h);
            if sock.is_active() && (sock.may_recv() || sock.may_send()) {
                    // Promote to managed connection entry
                    let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                    drop(sockets);
                    let mut conns = self.conns.lock();
                    conns.insert(id, ConnectionEntry {
                        id,
                        tcp: h,
                        last_activity_ms: now,
                        closed: false,
                    });
                    return Ok(id);
                }
        }
        Err("no pending connection")
    }
}

/* ===== TCP client (dial) ===== */

impl NetworkStack {
    // relay.rs name/signature (IpAddress enum)
    pub fn connect_tcp(&self, addr: IpAddress, port: u16) -> Result<(), &'static str> {
        let v4 = match addr {
            IpAddress::V4(a) => a,
            IpAddress::V6(_) => return Err("ipv6 not supported here"),
        };
        let tmp = TcpSocket::new();
        self.tcp_connect(&tmp, v4, port)
    }

    // real_network.rs uses this (explicit socket + v4 address)
    pub fn tcp_connect(&self, sock: &TcpSocket, addr_v4: [u8; 4], port: u16) -> Result<(), &'static str> {
        let mut sockets = self.sockets.lock();
        let tcp_rx = tcp::SocketBuffer::new(vec![0; 16384]);
        let tcp_tx = tcp::SocketBuffer::new(vec![0; 16384]);
        let mut s = tcp::Socket::new(tcp_rx, tcp_tx);

        s.set_timeout(Some(SmolDuration::from_millis(10_000)));
        let handle = sockets.add(s);

        // register conn entry
        let id = sock.connection_id();
        {
            let mut conns = self.conns.lock();
            conns.insert(id, ConnectionEntry {
                id,
                tcp: handle,
                last_activity_ms: now_ms(),
                closed: false,
            });
        }
        drop(sockets);

        // Initiate connect with proper smoltcp 0.11.0 Context
        {
            let mut sockets = self.sockets.lock();
            let mut iface = self.iface.lock();
            let socket: &mut tcp::Socket = sockets.get_mut(handle);
            let endpoint = smoltcp::wire::IpEndpoint::new(SmolIpAddress::Ipv4(SmolIpv4Address::new(addr_v4[0], addr_v4[1], addr_v4[2], addr_v4[3])), port);
            let local_endpoint = (SmolIpAddress::Ipv4(SmolIpv4Address::new(0, 0, 0, 0)), 0);
            let now = smoltcp::time::Instant::from_millis(now_ms() as i64);
            let mut ctx = iface.context();
            socket.connect(&mut ctx, local_endpoint, endpoint).map_err(|_| "tcp connect error")?;
        }

        // Poll until established or timeout
        let start = now_ms();
        loop {
            {
                let sockets = self.sockets.lock();
                let s: &tcp::Socket = sockets.get(handle);
                if s.is_active() && s.may_send() {
                    break;
                }
            }
            self.poll();
            if now_ms().saturating_sub(start) > 15_000 {
                return Err("tcp connect timeout");
            }
            crate::time::yield_now();
        }
        Ok(())
    }

    pub fn get_local_port(&self, sock: &TcpSocket) -> Option<u16> {
        let conns = self.conns.lock();
        let c = conns.get(&sock.connection_id())?;
        let sockets = self.sockets.lock();
        let s: &tcp::Socket = sockets.get(c.tcp);
        s.local_endpoint().map(|ep| ep.port)
    }
}

/* ===== TCP I/O ===== */

impl NetworkStack {
    pub fn tcp_send(&self, conn_id: u32, buf: &[u8]) -> Result<usize, &'static str> {
        let handle = {
            let mut conns = self.conns.lock();
            let c = conns.get_mut(&conn_id).ok_or("no such connection")?;
            if c.closed { return Err("closed"); }
            c.last_activity_ms = now_ms();
            c.tcp
        };

        let mut sent = 0usize;
        let start = now_ms();
        loop {
            {
                let mut sockets = self.sockets.lock();
                let s: &mut tcp::Socket = sockets.get_mut(handle);
                if !s.may_send() {
                    return Err("send not permitted");
                }
                match s.send_slice(&buf[sent..]) {
                    Ok(n) if n > 0 => {
                        sent += n;
                        let mut stats = self.stats.lock();
                        stats.tx_packets += 1;
                        stats.tx_bytes += n as u64;
                        if sent == buf.len() {
                            break;
                        }
                    }
                    Ok(_) | Err(_) => { /* backpressure, keep polling */ }
                }
            }
            self.poll();
            if now_ms().saturating_sub(start) > 15_000 {
                return Err("send timeout");
            }
            crate::time::yield_now();
        }
        Ok(sent)
    }

    pub fn tcp_receive(&self, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
        let handle = {
            let conns = self.conns.lock();
            let c = conns.get(&conn_id).ok_or("no such connection")?;
            c.tcp
        };

        let mut out = Vec::new();
        let start = now_ms();
        loop {
            {
                let mut sockets = self.sockets.lock();
                let s: &mut tcp::Socket = sockets.get_mut(handle);
                let available = s.recv_queue();
                if available > 0 {
                    let to_take = min(available, max_len);
                    out.resize(to_take, 0);
                    match s.recv_slice(&mut out) {
                        Ok(n) if n > 0 => {
                            let mut stats = self.stats.lock();
                            stats.rx_packets += 1;
                            stats.rx_bytes += n as u64;
                            out.truncate(n);
                            return Ok(out);
                        }
                        _ => {}
                    }
                } else if !s.can_recv() && !s.may_send() {
                    // closed
                    return Ok(Vec::new());
                }
            }
            self.poll();
            if now_ms().saturating_sub(start) > 15_000 {
                // no data within timeout; return empty (non-blocking semantics)
                return Ok(Vec::new());
            }
            crate::time::yield_now();
        }
    }

    pub fn tcp_is_closed(&self, conn_id: u32) -> Option<bool> {
        let conns = self.conns.lock();
        let c = conns.get(&conn_id)?;
        let sockets = self.sockets.lock();
        let s: &tcp::Socket = sockets.get(c.tcp);
        Some(!s.is_active())
    }

    pub fn tcp_close(&self, conn_id: u32) -> Result<(), &'static str> {
        let handle = {
            let mut conns = self.conns.lock();
            let c = conns.get_mut(&conn_id).ok_or("no such connection")?;
            c.closed = true;
            c.tcp
        };
        {
            let mut sockets = self.sockets.lock();
            let s: &mut tcp::Socket = sockets.get_mut(handle);
            let _ = s.close();
        }
        Ok(())
    }
}

/* ===== Legacy for relay.rs (send/recv) ===== */

impl NetworkStack {
    pub fn send_tcp_data(&self, socket: &Socket, data: &[u8]) -> Result<usize, &'static str> {
        let id = if let Some(id) = socket.connection_id() {
            id
        } else if let Some(id) = self.pick_single_active_conn() {
            id
        } else {
            return Err("no unambiguous connection for legacy Socket");
        };
        self.tcp_send(id, data)
    }

    pub fn recv_tcp_data(&self, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
        self.tcp_receive(conn_id, max_len)
    }
}

/* ===== HTTP/1.1 client (bounded) ===== */

impl NetworkStack {
    pub fn http_request(&self, addr: [u8; 4], port: u16, req: &[u8]) -> Result<Vec<u8>, &'static str> {
        let tmp = TcpSocket::new();
        self.tcp_connect(&tmp, addr, port)?;
        let id = tmp.connection_id();
        let _ = self.tcp_send(id, req)?;
        // Read until headers parsed + content-length satisfied or close (cap 5 MiB)
        const CAP: usize = 5 * 1024 * 1024;
        let mut buf = Vec::with_capacity(4096);
        let mut headers_done = false;
        let mut content_length: Option<usize> = None;

        let start = now_ms();
        loop {
            let chunk = self.tcp_receive(id, 4096)?;
            if !chunk.is_empty() {
                if buf.len() + chunk.len() > CAP { let _ = self.tcp_close(id); return Err("http cap exceeded"); }
                buf.extend_from_slice(&chunk);
            }
            if !headers_done {
                if let Some(idx) = find_subsequence(&buf, b"\r\n\r\n") {
                    headers_done = true;
                    // parse headers
                    let headers = &buf[..idx+4];
                    if !headers.starts_with(b"HTTP/1.1 200") && !headers.starts_with(b"HTTP/1.0 200") {
                        let _ = self.tcp_close(id);
                        return Err("http non-200");
                    }
                    for line in headers.split(|&b| b == b'\n') {
                        if line.len() >= 18 && starts_no_case(line, b"content-length:") {
                            if let Ok(n) = parse_usize_ascii(&line[15..]) { content_length = Some(n); }
                        }
                    }
                    if let Some(n) = content_length {
                        let body_len = buf.len() - (idx + 4);
                        if body_len >= n { break; }
                    }
                }
            } else if let Some(n) = content_length {
                if let Some(idx) = find_subsequence(&buf, b"\r\n\r\n") {
                    let body_len = buf.len() - (idx + 4);
                    if body_len >= n { break; }
                }
            }
            if now_ms().saturating_sub(start) > 20_000 { break; }
            self.poll();
            crate::time::yield_now();
        }

        // Close connection
        let _ = self.tcp_close(id);
        Ok(buf)
    }
}

/* ===== DNS helpers used by nonos_dns.rs ===== */

impl NetworkStack {
    pub fn set_default_dns_v4(&self, v4: [u8; 4]) { *self.default_dns_v4.lock() = v4; }

    pub fn dns_query_a(&self, hostname: &str, timeout_ms: u64) -> Result<Vec<[u8; 4]>, &'static str> {
        use smoltcp::socket::udp::{PacketBuffer, PacketMetadata};
        let mut sockets = self.sockets.lock();
        let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
        let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 8], vec![0; 1536]);
        let handle = sockets.add(udp::Socket::new(rx, tx));
        drop(sockets);

        let server = *self.default_dns_v4.lock();
        let query = build_dns_query(hostname);

        // Bind and send
        {
            let mut sockets = self.sockets.lock();
            let s: &mut udp::Socket = sockets.get_mut(handle);
            s.bind(0).map_err(|_| "dns bind")?;
            let dns_endpoint = smoltcp::wire::IpEndpoint::new(SmolIpAddress::Ipv4(SmolIpv4Address::new(server[0], server[1], server[2], server[3])), 53);
            let metadata = smoltcp::socket::udp::UdpMetadata::from(dns_endpoint);
            let _ = s.send_slice(&query, metadata).map_err(|_| "dns send")?;
        }

        let start = now_ms();
        loop {
            {
                let mut sockets = self.sockets.lock();
                let s: &mut udp::Socket = sockets.get_mut(handle);
                if let Ok((data, _ep)) = s.recv() {
                    let addrs = parse_dns_response_a(&data)?;
                    sockets.remove(handle);
                    return Ok(addrs);
                }
            }
            self.poll();
            if now_ms().saturating_sub(start) > timeout_ms {
                let mut sockets = self.sockets.lock();
                sockets.remove(handle);
                return Err("dns timeout");
            }
            crate::time::yield_now();
        }
    }
}

/* ===== Extra: best-effort "send_tcp_packet" used by circuit.rs ===== */

impl NetworkStack {
    pub fn send_tcp_packet(&self, data: &[u8]) -> Result<(), &'static str> {
        if let Some(id) = self.pick_single_active_conn() {
            let _ = self.tcp_send(id, data)?;
            Ok(())
        } else {
            Err("no active tcp connection to send packet")
        }
    }
}

/* ===== helpers ===== */

fn starts_no_case(s: &[u8], pref: &[u8]) -> bool {
    if s.len() < pref.len() { return false }
    s[..pref.len()].eq_ignore_ascii_case(pref)
}

fn parse_usize_ascii(s: &[u8]) -> Result<usize, ()> {
    let mut n: usize = 0;
    for &b in s {
        if b == b' ' || b == b'\r' { break; }
        if !(b'0'..=b'9').contains(&b) { return Err(()); }
        n = n.saturating_mul(10).saturating_add((b - b'0') as usize);
    }
    Ok(n)
}

fn find_subsequence(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() { return Some(0); }
    h.windows(n.len()).position(|w| w == n)
}

// Minimal RFC1035 A query builder/decoder (bounds-checked)

fn build_dns_query(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // header
    out.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // rd
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&0u16.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // qname
    for label in name.split('.') {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > 63 { continue; }
        out.push(lb.len() as u8);
        out.extend_from_slice(lb);
    }
    out.push(0);
    // qtype A
    out.extend_from_slice(&1u16.to_be_bytes());
    // qclass IN
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

fn parse_dns_response_a(data: &[u8]) -> Result<Vec<[u8; 4]>, &'static str> {
    if data.len() < 12 { return Err("dns short"); }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    // skip header + question
    let mut off = 12usize;
    for _ in 0..qd {
        while off < data.len() && data[off] != 0 {
            off += 1 + data[off] as usize;
        }
        off = off.saturating_add(1); // zero
        off = off.saturating_add(4); // qtype+qclass
        if off > data.len() { return Err("dns malformed qd"); }
    }

    // answers
    let mut out = Vec::new();
    for _ in 0..an {
        if off + 10 > data.len() { break; }
        // name (skip: compressed or labels)
        if data[off] & 0xC0 == 0xC0 {
            off = off.saturating_add(2);
        } else {
            while off < data.len() && data[off] != 0 {
                off = off.saturating_add(1 + data[off] as usize);
            }
            off = off.saturating_add(1);
        }
        if off + 10 > data.len() { break; }
        let typ = u16::from_be_bytes([data[off], data[off+1]]); off += 2;
        off += 2; // class
        off += 4; // ttl
        let rdlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off += 2;
        if typ == 1 && rdlen == 4 && off + 4 <= data.len() {
            let mut a = [0u8; 4];
            a.copy_from_slice(&data[off..off+4]);
            out.push(a);
        }
        off = off.saturating_add(rdlen);
    }
    Ok(out)
}
