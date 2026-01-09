// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};

pub trait NetworkInterface: Send + Sync + 'static {
    fn send_packet(&self, frame: &[u8]) -> Result<(), &'static str>;
    fn get_mac_address(&self) -> [u8; 6];
    fn is_link_up(&self) -> bool;
    fn get_stats(&self) -> NetworkStats;
    fn mtu(&self) -> usize {
        1500
    }
    fn name(&self) -> &'static str {
        "iface"
    }
}

#[derive(Default)]
pub struct NetworkStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub active_sockets: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub arp_lookups: AtomicU64,
}

static IFACES: Mutex<BTreeMap<&'static str, Arc<dyn NetworkInterface>>> =
    Mutex::new(BTreeMap::new());
static DEFAULT_IFACE: Mutex<Option<Arc<dyn NetworkInterface>>> = Mutex::new(None);

static LOCAL_MAC: RwLock<[u8; 6]> = RwLock::new([0; 6]);
static LOCAL_IP: RwLock<[u8; 4]> = RwLock::new([0, 0, 0, 0]);
static DEFAULT_GW: RwLock<[u8; 4]> = RwLock::new([0, 0, 0, 0]);

pub fn register_interface(name: &'static str, iface: Arc<dyn NetworkInterface>, make_default: bool) {
    IFACES.lock().insert(name, iface.clone());
    if make_default {
        *DEFAULT_IFACE.lock() = Some(iface.clone());
        *LOCAL_MAC.write() = iface.get_mac_address();
    }
}

pub fn set_default_interface(name: &str) -> Result<(), &'static str> {
    let iface = IFACES.lock().get(name).cloned().ok_or("iface not found")?;
    *DEFAULT_IFACE.lock() = Some(iface);
    Ok(())
}

pub fn get_default_interface() -> Option<Arc<dyn NetworkInterface>> {
    DEFAULT_IFACE.lock().as_ref().cloned()
}

pub fn set_ipv4(ip: [u8; 4], gw: Option<[u8; 4]>) {
    *LOCAL_IP.write() = ip;
    if let Some(g) = gw {
        *DEFAULT_GW.write() = g;
    }
}

pub fn get_ipv4() -> [u8; 4] {
    *LOCAL_IP.read()
}

pub fn get_mac() -> [u8; 6] {
    *LOCAL_MAC.read()
}

pub enum FilterAction {
    Accept,
    Drop,
}

pub trait PacketFilter: Send + Sync + 'static {
    fn pre_recv(&self, _frame: &[u8]) -> FilterAction {
        FilterAction::Accept
    }
    fn post_recv(&self, _ethertype: u16, _payload: &[u8]) -> FilterAction {
        FilterAction::Accept
    }
    fn pre_send(&self, _frame: &[u8]) -> FilterAction {
        FilterAction::Accept
    }
}

static FILTERS: Mutex<Vec<Arc<dyn PacketFilter>>> = Mutex::new(Vec::new());

pub fn add_filter(f: Arc<dyn PacketFilter>) {
    FILTERS.lock().push(f);
}

fn run_pre(frame: &[u8]) -> bool {
    for f in FILTERS.lock().iter() {
        if matches!(f.pre_recv(frame), FilterAction::Drop) {
            return false;
        }
    }
    true
}

fn run_post(ethertype: u16, payload: &[u8]) -> bool {
    for f in FILTERS.lock().iter() {
        if matches!(f.post_recv(ethertype, payload), FilterAction::Drop) {
            return false;
        }
    }
    true
}

fn run_send(frame: &[u8]) -> bool {
    for f in FILTERS.lock().iter() {
        if matches!(f.pre_send(frame), FilterAction::Drop) {
            return false;
        }
    }
    true
}

const ETH_HDR: usize = 14;
const ET_IPV4: u16 = 0x0800;
const ET_ARP: u16 = 0x0806;

#[repr(C, packed)]
struct EthHeader {
    dst: [u8; 6],
    src: [u8; 6],
    et_be: [u8; 2],
}

#[inline]
fn be16(b: [u8; 2]) -> u16 {
    u16::from_be_bytes(b)
}

#[inline]
fn to_be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

#[inline]
fn to_be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

static ARP_CACHE: Mutex<BTreeMap<[u8; 4], [u8; 6]>> = Mutex::new(BTreeMap::new());

pub fn arp_lookup(ip: [u8; 4]) -> Option<[u8; 6]> {
    ARP_CACHE.lock().get(&ip).cloned()
}

pub fn arp_insert(ip: [u8; 4], mac: [u8; 6]) {
    ARP_CACHE.lock().insert(ip, mac);
}

fn send_arp_request(target_ip: [u8; 4]) -> Result<(), &'static str> {
    let iface = get_default_interface().ok_or("no default iface")?;
    let src_mac = iface.get_mac_address();
    let src_ip = get_ipv4();
    let mut frame = [0u8; ETH_HDR + 28];
    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&to_be16(ET_ARP));
    let p = &mut frame[ETH_HDR..];
    p[0..2].copy_from_slice(&to_be16(1));
    p[2..4].copy_from_slice(&to_be16(ET_IPV4));
    p[4] = 6;
    p[5] = 4;
    p[6..8].copy_from_slice(&to_be16(1));
    p[8..14].copy_from_slice(&src_mac);
    p[14..18].copy_from_slice(&src_ip);
    p[18..24].copy_from_slice(&[0u8; 6]);
    p[24..28].copy_from_slice(&target_ip);
    if !run_send(&frame) {
        return Err("send filtered");
    }
    iface.send_packet(&frame)
}

fn handle_arp(payload: &[u8]) {
    if payload.len() < 28 {
        crate::log_warn!("network: ARP packet too short ({} < 28)", payload.len());
        return;
    }
    let oper = be16([payload[6], payload[7]]);
    let sha = <[u8; 6]>::try_from(&payload[8..14]).unwrap_or([0; 6]);
    let spa = <[u8; 4]>::try_from(&payload[14..18]).unwrap_or([0; 4]);
    let tha = <[u8; 6]>::try_from(&payload[18..24]).unwrap_or([0; 6]);
    let tpa = <[u8; 4]>::try_from(&payload[24..28]).unwrap_or([0; 4]);
    arp_insert(spa, sha);
    if oper == 1 && tpa == get_ipv4() {
        if let Some(iface) = get_default_interface() {
            let src_mac = iface.get_mac_address();
            let src_ip = get_ipv4();
            let mut frame = [0u8; ETH_HDR + 28];
            frame[0..6].copy_from_slice(&sha);
            frame[6..12].copy_from_slice(&src_mac);
            frame[12..14].copy_from_slice(&to_be16(ET_ARP));
            let p = &mut frame[ETH_HDR..];
            p[0..2].copy_from_slice(&to_be16(1));
            p[2..4].copy_from_slice(&to_be16(ET_IPV4));
            p[4] = 6;
            p[5] = 4;
            p[6..8].copy_from_slice(&to_be16(2));
            p[8..14].copy_from_slice(&src_mac);
            p[14..18].copy_from_slice(&src_ip);
            p[18..24].copy_from_slice(&tha);
            p[24..28].copy_from_slice(&spa);
            if let Err(e) = iface.send_packet(&frame) {
                crate::log_warn!("network: ARP reply send failed: {}", e);
            }
        }
    }
}

#[repr(C, packed)]
struct Ipv4Header {
    vihl: u8,
    dscp_ecn: u8,
    total_len_be: [u8; 2],
    id_be: [u8; 2],
    flags_frag_be: [u8; 2],
    ttl: u8,
    proto: u8,
    hdr_checksum_be: [u8; 2],
    src: [u8; 4],
    dst: [u8; 4],
}

#[repr(C, packed)]
struct UdpHeader {
    sport_be: [u8; 2],
    dport_be: [u8; 2],
    len_be: [u8; 2],
    csum_be: [u8; 2],
}

const IP_PROTO_UDP: u8 = 17;

fn csum16(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn ip_checksum(h: &Ipv4Header) -> u16 {
    // SAFETY: Ipv4Header is repr(C, packed) and exactly 20 bytes
    let w = unsafe { core::slice::from_raw_parts(h as *const _ as *const u16, 10) };
    let mut sum = 0u32;
    for (i, v) in w.iter().enumerate() {
        if i == 5 {
            continue;
        }
        sum += u16::from_be(*v) as u32;
    }
    csum16(sum)
}

fn udp_checksum(ip: &Ipv4Header, udp: &UdpHeader, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += u16::from_be_bytes([ip.src[0], ip.src[1]]) as u32;
    sum += u16::from_be_bytes([ip.src[2], ip.src[3]]) as u32;
    sum += u16::from_be_bytes([ip.dst[0], ip.dst[1]]) as u32;
    sum += u16::from_be_bytes([ip.dst[2], ip.dst[3]]) as u32;
    sum += IP_PROTO_UDP as u32;
    let udp_len = u16::from_be_bytes(udp.len_be) as u32;
    sum += udp_len;
    // SAFETY: UdpHeader is repr(C, packed) and exactly 8 bytes
    let uw = unsafe { core::slice::from_raw_parts(udp as *const _ as *const u16, 4) };
    for v in uw {
        sum += u16::from_be(*v) as u32;
    }
    let mut i = 0;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += u16::from_be_bytes([payload[i], 0]) as u32;
    }
    csum16(sum)
}

type UdpHandler = Arc<dyn Fn(&[u8], [u8; 4], u16) + Send + Sync>;
static UDP_LISTENERS: Mutex<BTreeMap<u16, UdpHandler>> = Mutex::new(BTreeMap::new());

pub fn udp_listen(port: u16, handler: UdpHandler) {
    UDP_LISTENERS.lock().insert(port, handler);
}

pub fn udp_send(
    dst_ip: [u8; 4],
    dst_port: u16,
    src_port: u16,
    payload: &[u8],
) -> Result<(), &'static str> {
    let iface = get_default_interface().ok_or("no default iface")?;
    let src_mac = iface.get_mac_address();
    let dst_mac = if let Some(m) = arp_lookup(dst_ip) {
        m
    } else {
        let _ = send_arp_request(dst_ip);
        return Err("ARP unresolved");
    };
    let src_ip = get_ipv4();
    let mtu = iface.mtu();
    let overhead = ETH_HDR + 20 + 8;
    if payload.len() + overhead > mtu {
        return Err("payload exceeds MTU");
    }
    let total = overhead + payload.len();
    let mut frame = alloc::vec![0u8; total];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&to_be16(ET_IPV4));
    let ip_off = ETH_HDR;
    {
        let hdr = Ipv4Header {
            vihl: (4 << 4) | 5,
            dscp_ecn: 0,
            total_len_be: (20u16 + 8 + payload.len() as u16).to_be_bytes(),
            id_be: 0u16.to_be_bytes(),
            flags_frag_be: 0u16.to_be_bytes(),
            ttl: 64,
            proto: IP_PROTO_UDP,
            hdr_checksum_be: [0, 0],
            src: src_ip,
            dst: dst_ip,
        };
        // SAFETY: frame buffer is properly sized, ip_off is within bounds
        unsafe {
            core::ptr::copy_nonoverlapping(
                &hdr as *const _ as *const u8,
                frame.as_mut_ptr().add(ip_off),
                mem::size_of::<Ipv4Header>(),
            );
        }
        // SAFETY: frame contains valid Ipv4Header at ip_off, using read_unaligned for packed struct.
        let ip_hdr: Ipv4Header =
            unsafe { core::ptr::read_unaligned(frame.as_ptr().add(ip_off) as *const Ipv4Header) };
        let c = ip_checksum(&ip_hdr);
        let checksum_bytes = c.to_be_bytes();
        frame[ip_off + 10] = checksum_bytes[0];
        frame[ip_off + 11] = checksum_bytes[1];
    }
    let udp_off = ip_off + 20;
    {
        let hdr = UdpHeader {
            sport_be: src_port.to_be_bytes(),
            dport_be: dst_port.to_be_bytes(),
            len_be: (8 + payload.len() as u16).to_be_bytes(),
            csum_be: [0, 0],
        };
        // SAFETY: frame buffer is properly sized, udp_off is within bounds
        unsafe {
            core::ptr::copy_nonoverlapping(
                &hdr as *const _ as *const u8,
                frame.as_mut_ptr().add(udp_off),
                mem::size_of::<UdpHeader>(),
            );
        }
        frame[udp_off + 8..udp_off + 8 + payload.len()].copy_from_slice(payload);
        // SAFETY: frame contains valid headers, using read_unaligned for packed structs.
        let udp_hdr: UdpHeader =
            unsafe { core::ptr::read_unaligned(frame.as_ptr().add(udp_off) as *const UdpHeader) };
        let ip_hdr: Ipv4Header =
            unsafe { core::ptr::read_unaligned(frame.as_ptr().add(ip_off) as *const Ipv4Header) };
        let c = udp_checksum(&ip_hdr, &udp_hdr, &frame[udp_off + 8..]);
        let checksum_bytes = c.to_be_bytes();
        frame[udp_off + 6] = checksum_bytes[0];
        frame[udp_off + 7] = checksum_bytes[1];
    }
    if !run_send(&frame) {
        return Err("send filtered");
    }
    iface.send_packet(&frame)
}

pub fn receive_packet(frame: &[u8]) -> Result<(), &'static str> {
    if !run_pre(frame) {
        return Err("filtered pre-recv");
    }
    if frame.len() < ETH_HDR {
        return Err("frame too short");
    }
    let mut eth = EthHeader {
        dst: [0; 6],
        src: [0; 6],
        et_be: [0; 2],
    };
    eth.dst.copy_from_slice(&frame[0..6]);
    eth.src.copy_from_slice(&frame[6..12]);
    eth.et_be.copy_from_slice(&frame[12..14]);
    let et = be16(eth.et_be);
    let payload = &frame[ETH_HDR..];
    if !run_post(et, payload) {
        return Err("filtered post-recv");
    }
    match et {
        ET_ARP => {
            handle_arp(payload);
            Ok(())
        }
        ET_IPV4 => {
            if payload.len() < 20 {
                return Err("ipv4 too short");
            }
            // SAFETY: payload length checked, using read_unaligned for packed struct.
            let ip: Ipv4Header =
                unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const Ipv4Header) };
            if (ip.vihl >> 4) != 4 || (ip.vihl & 0x0F) != 5 {
                return Err("ipv4 header invalid");
            }
            if ip.proto == IP_PROTO_UDP {
                if payload.len() < 28 {
                    return Err("udp too short");
                }
                let udp_off = 20;
                // SAFETY: payload length checked, using read_unaligned for packed struct.
                let udp: UdpHeader = unsafe {
                    core::ptr::read_unaligned(payload.as_ptr().add(udp_off) as *const UdpHeader)
                };
                let dport = u16::from_be_bytes(udp.dport_be);
                let sport = u16::from_be_bytes(udp.sport_be);
                let ulen = u16::from_be_bytes(udp.len_be) as usize;
                if ulen < 8 || udp_off + ulen > payload.len() {
                    return Err("udp len invalid");
                }
                let data = &payload[udp_off + 8..udp_off + ulen];
                if let Some(h) = UDP_LISTENERS.lock().get(&dport).cloned() {
                    h(data, ip.src, sport);
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn try_send_raw(frame: &[u8]) -> Result<(), &'static str> {
    if let Some(iface) = get_default_interface() {
        if !run_send(frame) {
            return Err("send filtered");
        }
        iface.send_packet(frame)
    } else {
        Err("no default interface")
    }
}
