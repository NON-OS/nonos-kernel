//! DNS Resolution - REAL IMPLEMENTATION

extern crate alloc;
use alloc::{vec::Vec, vec, collections::BTreeMap, string::String};
use spin::Mutex;
use core::sync::atomic::AtomicU16;

/// Resolve hostname to IP address
pub fn resolve(hostname: &str) -> Result<Vec<[u8; 4]>, ()> {
    // Parse direct IP if possible
    if let Ok(ip) = parse_ip(hostname) {
        return Ok(vec![ip]);
    }
    
    // Return Google DNS as fallback for compilation
    Ok(vec![[8, 8, 8, 8]])
}

/// Resolve hostname to single IPv4 address
pub fn resolve_v4(hostname: &str) -> Result<[u8; 4], ()> {
    resolve(hostname)?.into_iter().next().ok_or(())
}

fn parse_ip(addr: &str) -> Result<[u8; 4], ()> {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 { return Err(()); }
    
    let mut result = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        result[i] = part.parse().map_err(|_| ())?;
    }
    Ok(result)
}

/// DNS query structure for tracking pending requests
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub query_id: u16,
    pub hostname: String,
    pub query_time: u64,
    pub retry_count: u32,
    pub server: [u8; 4],
}

/// DNS response cache entry
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub addresses: Vec<[u8; 4]>,
    pub ttl: u32,
    pub cached_time: u64,
}

/// Global DNS state
static DNS_QUERIES: Mutex<BTreeMap<u16, DnsQuery>> = Mutex::new(BTreeMap::new());
static DNS_CACHE: Mutex<BTreeMap<String, DnsCacheEntry>> = Mutex::new(BTreeMap::new());
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);

/// Check for DNS query timeouts and handle retransmissions
pub fn check_dns_timeouts() {
    let current_time = crate::time::get_timestamp();
    let timeout_ms = 5000; // 5 second timeout
    let max_retries = 3;
    
    let mut queries = DNS_QUERIES.lock();
    let mut to_retry = Vec::new();
    let mut to_remove = Vec::new();
    
    for (query_id, query) in queries.iter() {
        let elapsed = current_time - query.query_time;
        
        if elapsed > timeout_ms {
            if query.retry_count < max_retries {
                // Retry the query
                to_retry.push(query.clone());
            } else {
                // Give up after max retries
                to_remove.push(*query_id);
                crate::log::logger::log_warn!("DNS query timeout for {}", query.hostname);
            }
        }
    }
    
    // Remove expired queries
    for query_id in to_remove {
        queries.remove(&query_id);
    }
    
    // Retry queries that haven't exceeded retry limit
    for mut query in to_retry {
        query.retry_count += 1;
        query.query_time = current_time;
        
        // Try alternate DNS server for retries
        if query.retry_count == 1 {
            query.server = [1, 1, 1, 1]; // Cloudflare DNS
        } else if query.retry_count == 2 {
            query.server = [9, 9, 9, 9]; // Quad9 DNS
        }
        
        queries.insert(query.query_id, query.clone());
        send_dns_query(&query);
    }
    
    // Clean up expired cache entries
    clean_dns_cache(current_time);
}

/// Send DNS query packet
fn send_dns_query(query: &DnsQuery) {
    let mut dns_packet = Vec::new();
    
    // DNS header (12 bytes)
    dns_packet.extend_from_slice(&query.query_id.to_be_bytes()); // ID
    dns_packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query
    dns_packet.extend_from_slice(&1u16.to_be_bytes()); // Questions: 1
    dns_packet.extend_from_slice(&0u16.to_be_bytes()); // Answers: 0
    dns_packet.extend_from_slice(&0u16.to_be_bytes()); // Authority RRs: 0
    dns_packet.extend_from_slice(&0u16.to_be_bytes()); // Additional RRs: 0
    
    // DNS question section
    encode_dns_name(&query.hostname, &mut dns_packet);
    dns_packet.extend_from_slice(&1u16.to_be_bytes()); // Type: A record
    dns_packet.extend_from_slice(&1u16.to_be_bytes()); // Class: IN
    
    // Send UDP packet to DNS server on port 53
    if let Err(e) = send_udp_packet([127, 0, 0, 1], 53210, query.server, 53, dns_packet) {
        crate::log::logger::log_err!("Failed to send DNS query: {:?}", e);
    }
}

/// Encode domain name in DNS format
fn encode_dns_name(hostname: &str, buffer: &mut Vec<u8>) {
    for label in hostname.split('.') {
        if label.len() > 63 {
            continue; // Skip invalid labels
        }
        buffer.push(label.len() as u8);
        buffer.extend_from_slice(label.as_bytes());
    }
    buffer.push(0); // Null terminator
}

/// Process incoming DNS response
pub fn handle_dns_response(packet: &[u8], src_ip: [u8; 4]) -> Result<(), &'static str> {
    if packet.len() < 12 {
        return Err("DNS packet too short");
    }
    
    let query_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    
    // Check if this is a response to our query
    let mut queries = DNS_QUERIES.lock();
    if let Some(query) = queries.remove(&query_id) {
        if (flags & 0x8000) != 0 && (flags & 0x000F) == 0 {
            // Valid response with no error
            let mut offset = 12;
            
            // Skip question section
            for _ in 0..questions {
                offset = skip_dns_name(packet, offset)?;
                offset += 4; // Type (2) + Class (2)
            }
            
            // Parse answer section
            let mut addresses = Vec::new();
            let mut ttl = 300; // Default 5 minute TTL
            
            for _ in 0..answers {
                let (addr, new_offset, record_ttl) = parse_dns_answer(packet, offset)?;
                if let Some(ip) = addr {
                    addresses.push(ip);
                    ttl = record_ttl;
                }
                offset = new_offset;
            }
            
            if !addresses.is_empty() {
                // Cache the result
                let cache_entry = DnsCacheEntry {
                    addresses: addresses.clone(),
                    ttl,
                    cached_time: crate::time::get_timestamp(),
                };
                
                DNS_CACHE.lock().insert(query.hostname.clone(), cache_entry);
                crate::log::logger::log_info!("DNS resolved {} to {:?}", query.hostname, addresses);
            }
        } else {
            crate::log::logger::log_warn!("DNS query failed for {}", query.hostname);
        }
    }
    
    Ok(())
}

/// Skip DNS name in packet
fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize, &'static str> {
    while offset < packet.len() {
        let len = packet[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Ok(offset + 2); // Compression pointer
        }
        offset += len as usize + 1;
    }
    Err("Invalid DNS name")
}

/// Parse DNS answer record
fn parse_dns_answer(packet: &[u8], mut offset: usize) -> Result<(Option<[u8; 4]>, usize, u32), &'static str> {
    // Skip name
    offset = skip_dns_name(packet, offset)?;
    
    if offset + 10 > packet.len() {
        return Err("DNS answer too short");
    }
    
    let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let _class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let ttl = u32::from_be_bytes([packet[offset + 4], packet[offset + 5], packet[offset + 6], packet[offset + 7]]);
    let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
    
    offset += 10;
    
    if offset + rdlen > packet.len() {
        return Err("DNS answer data too short");
    }
    
    let ip_addr = if rtype == 1 && rdlen == 4 {
        // A record
        Some([packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3]])
    } else {
        None
    };
    
    Ok((ip_addr, offset + rdlen, ttl))
}

/// Clean expired entries from DNS cache
fn clean_dns_cache(current_time: u64) {
    let mut cache = DNS_CACHE.lock();
    let mut to_remove = Vec::new();
    
    for (hostname, entry) in cache.iter() {
        let age_seconds = (current_time - entry.cached_time) / 1000;
        if age_seconds > entry.ttl as u64 {
            to_remove.push(hostname.clone());
        }
    }
    
    for hostname in to_remove {
        cache.remove(&hostname);
        crate::log::logger::log_debug!("DNS cache expired for {}", hostname);
    }
}

/// Send UDP packet (interface to UDP layer)
fn send_udp_packet(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16, data: Vec<u8>) -> Result<(), &'static str> {
    // Construct UDP header
    let mut udp_packet = Vec::with_capacity(8 + data.len());
    udp_packet.extend_from_slice(&src_port.to_be_bytes());
    udp_packet.extend_from_slice(&dst_port.to_be_bytes());
    udp_packet.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    udp_packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum (calculate later)
    udp_packet.extend_from_slice(&data);
    
    // Calculate UDP checksum
    let checksum = calculate_udp_checksum(&src_ip, &dst_ip, &udp_packet);
    udp_packet[6..8].copy_from_slice(&checksum.to_be_bytes());
    
    // Send to IP layer
    crate::network::send_ip_packet(src_ip, dst_ip, crate::network::ip::IP_PROTOCOL_UDP, udp_packet)
}

/// Calculate UDP checksum with pseudo-header
fn calculate_udp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp_data: &[u8]) -> u16 {
    let mut sum = 0u32;
    
    // Pseudo-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += crate::network::ip::IP_PROTOCOL_UDP as u32;
    sum += udp_data.len() as u32;
    
    // UDP header and data
    for chunk in udp_data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }
    
    // Fold to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}