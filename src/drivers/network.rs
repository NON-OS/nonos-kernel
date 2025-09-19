use alloc::{vec::Vec, string::String};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub struct NetworkInterface {
    interface_id: u32,
    interface_name: String,
    mac_address: [u8; 6],
    ip_address: [u8; 4],
    enabled: AtomicBool,
    packets_sent: AtomicU32,
    packets_received: AtomicU32,
    bytes_sent: AtomicU32,
    bytes_received: AtomicU32,
    interface_type: InterfaceType,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum InterfaceType {
    Ethernet = 1,
    WiFi = 2,
    Loopback = 3,
    Bluetooth = 4,
    Cellular = 5,
}

pub struct NetworkDriver {
    interfaces: Vec<NetworkInterface>,
    emergency_shutdown: AtomicBool,
    packet_filter_enabled: bool,
    intrusion_detection: bool,
    firewall_enabled: bool,
}

impl NetworkDriver {
    pub fn new() -> Self {
        NetworkDriver {
            interfaces: Vec::new(),
            emergency_shutdown: AtomicBool::new(false),
            packet_filter_enabled: true,
            intrusion_detection: true,
            firewall_enabled: true,
        }
    }

    pub fn register_interface(&mut self, name: String, mac: [u8; 6], interface_type: InterfaceType) -> u32 {
        let interface_id = self.interfaces.len() as u32;
        
        let interface = NetworkInterface {
            interface_id,
            interface_name: name,
            mac_address: mac,
            ip_address: [0, 0, 0, 0],
            enabled: AtomicBool::new(true),
            packets_sent: AtomicU32::new(0),
            packets_received: AtomicU32::new(0),
            bytes_sent: AtomicU32::new(0),
            bytes_received: AtomicU32::new(0),
            interface_type,
        };

        self.interfaces.push(interface);
        interface_id
    }

    pub fn send_packet(&mut self, interface_id: u32, data: &[u8], destination: &[u8; 6]) -> Result<(), &'static str> {
        if self.emergency_shutdown.load(Ordering::Relaxed) {
            return Err("Network interfaces disabled due to emergency shutdown");
        }

        if interface_id as usize >= self.interfaces.len() {
            return Err("Invalid interface ID");
        }

        let interface = &self.interfaces[interface_id as usize];
        
        if !interface.enabled.load(Ordering::Relaxed) {
            return Err("Network interface is disabled");
        }

        // Security checks
        if self.packet_filter_enabled && self.is_suspicious_packet(data) {
            return Err("Packet blocked by security filter");
        }

        if self.firewall_enabled && self.is_blocked_destination(destination) {
            return Err("Destination blocked by firewall");
        }

        // Simulate packet transmission
        self.transmit_ethernet_frame(interface, data, destination)?;
        
        // Update statistics
        interface.packets_sent.fetch_add(1, Ordering::Relaxed);
        interface.bytes_sent.fetch_add(data.len() as u32, Ordering::Relaxed);

        Ok(())
    }

    fn transmit_ethernet_frame(&self, interface: &NetworkInterface, data: &[u8], destination: &[u8; 6]) -> Result<(), &'static str> {
        // Build Ethernet frame
        let mut frame = Vec::with_capacity(data.len() + 14); // 14 bytes for Ethernet header
        
        // Destination MAC (6 bytes)
        frame.extend_from_slice(destination);
        
        // Source MAC (6 bytes)
        frame.extend_from_slice(&interface.mac_address);
        
        // EtherType (2 bytes) - IPv4
        frame.push(0x08);
        frame.push(0x00);
        
        // Payload
        frame.extend_from_slice(data);

        // Hardware transmission simulation
        self.hardware_transmit(&frame)?;

        crate::log::logger::log_info!("Transmitted {} byte frame on interface {}", 
            frame.len(), interface.interface_name);

        Ok(())
    }

    fn hardware_transmit(&self, frame: &[u8]) -> Result<(), &'static str> {
        // Simulate hardware-level frame transmission
        if frame.len() < 64 {
            return Err("Frame too small (minimum 64 bytes)");
        }
        
        if frame.len() > 1518 {
            return Err("Frame too large (maximum 1518 bytes)");
        }

        // CRC calculation and validation would happen here
        let crc = self.calculate_ethernet_crc(frame);
        
        // Physical layer transmission simulation
        self.physical_layer_transmit(frame, crc)
    }

    fn calculate_ethernet_crc(&self, data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        
        !crc
    }

    fn physical_layer_transmit(&self, frame: &[u8], crc: u32) -> Result<(), &'static str> {
        // Simulate physical transmission with error detection
        if frame.is_empty() {
            return Err("Cannot transmit empty frame");
        }

        // Simulate transmission timing and collision detection
        let transmission_time_us = (frame.len() * 8) / 10; // 10 Mbps simulation
        
        // Anti-collision and carrier sense
        if self.detect_carrier_collision() {
            return Err("Carrier collision detected");
        }

        crate::log::logger::log_info!("Physical transmission completed in {}μs (CRC: 0x{:08X})", 
            transmission_time_us, crc);

        Ok(())
    }

    fn detect_carrier_collision(&self) -> bool {
        // Simulate CSMA/CD collision detection
        false // Simplified - no collision
    }

    pub fn receive_packet(&mut self, interface_id: u32) -> Result<Vec<u8>, &'static str> {
        if self.emergency_shutdown.load(Ordering::Relaxed) {
            return Err("Network interfaces disabled due to emergency shutdown");
        }

        if interface_id as usize >= self.interfaces.len() {
            return Err("Invalid interface ID");
        }

        let interface = &self.interfaces[interface_id as usize];
        
        if !interface.enabled.load(Ordering::Relaxed) {
            return Err("Network interface is disabled");
        }

        // Simulate packet reception from hardware
        let received_frame = self.hardware_receive()?;
        
        // Validate Ethernet frame
        if received_frame.len() < 14 {
            return Err("Invalid Ethernet frame (too short)");
        }

        // Extract destination MAC
        let dest_mac = &received_frame[0..6];
        if dest_mac != interface.mac_address && dest_mac != &[0xFF; 6] {
            return Err("Frame not addressed to this interface");
        }

        // Extract payload (skip 14-byte Ethernet header)
        let payload = received_frame[14..].to_vec();

        // Security inspection
        if self.intrusion_detection && self.detect_intrusion_attempt(&payload) {
            crate::log::logger::log_info!("Intrusion attempt detected in received packet");
            return Err("Malicious packet blocked by intrusion detection");
        }

        // Update statistics
        interface.packets_received.fetch_add(1, Ordering::Relaxed);
        interface.bytes_received.fetch_add(payload.len() as u32, Ordering::Relaxed);

        crate::log::logger::log_info!("Received {} byte payload on interface {}", 
            payload.len(), interface.interface_name);

        Ok(payload)
    }

    fn hardware_receive(&self) -> Result<Vec<u8>, &'static str> {
        // Simulate hardware frame reception
        // This would normally read from network interface buffer
        
        // Simulate a basic Ethernet frame reception
        let mut frame = Vec::new();
        
        // Simulate received frame (example IPv4 ping)
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dest MAC
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Src MAC
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType (IPv4)
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x54]); // IPv4 header start
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // More IPv4 data
        
        Ok(frame)
    }

    fn is_suspicious_packet(&self, data: &[u8]) -> bool {
        // Deep packet inspection for security threats
        
        // Check for common attack patterns
        let malicious_patterns: [&[u8]; 8] = [
            b"../../../etc/passwd",
            b"<script>............",  // Pad to same length
            b"SELECT * FROM......",
            b"UNION SELECT.......",
            b"DROP TABLE.........",
            b"%2e%2e%2f..........",
            b"cmd.exe............",
            b"/bin/sh............",
        ];

        for pattern in &malicious_patterns {
            if self.boyer_moore_search(data, pattern) {
                return true;
            }
        }

        // Check for buffer overflow attempts
        if data.len() > 65536 {
            return true;
        }

        // Check for port scanning patterns
        if data.len() < 20 && data.iter().all(|&b| b == 0x00) {
            return true;
        }

        false
    }

    fn boyer_moore_search(&self, text: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || text.len() < pattern.len() {
            return false;
        }

        let mut bad_char_table = [pattern.len(); 256];
        for (i, &byte) in pattern.iter().enumerate() {
            if i < pattern.len() - 1 {
                bad_char_table[byte as usize] = pattern.len() - 1 - i;
            }
        }

        let mut i = 0;
        while i <= text.len() - pattern.len() {
            let mut j = pattern.len();
            while j > 0 && pattern[j - 1] == text[i + j - 1] {
                j -= 1;
            }

            if j == 0 {
                return true;
            }

            let bad_char_skip = if i + j < text.len() {
                bad_char_table[text[i + j] as usize]
            } else {
                1
            };

            i += bad_char_skip.max(1);
        }

        false
    }

    fn is_blocked_destination(&self, mac: &[u8; 6]) -> bool {
        // Firewall rules for MAC addresses
        let blocked_macs = [
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Null MAC
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Broadcast (conditional)
        ];

        blocked_macs.contains(mac)
    }

    fn detect_intrusion_attempt(&self, data: &[u8]) -> bool {
        // Advanced intrusion detection system

        // Check for DDoS patterns
        if self.is_ddos_pattern(data) {
            return true;
        }

        // Check for protocol anomalies
        if self.detect_protocol_anomaly(data) {
            return true;
        }

        // Check for reconnaissance attempts
        if self.is_reconnaissance_attempt(data) {
            return true;
        }

        false
    }

    fn is_ddos_pattern(&self, data: &[u8]) -> bool {
        // Detect DDoS attack patterns
        data.len() < 10 || (data.len() == 20 && data.iter().all(|&b| b == 0xAA))
    }

    fn detect_protocol_anomaly(&self, data: &[u8]) -> bool {
        // Check for malformed protocol headers
        if data.len() >= 4 {
            // Check IP version (should be 4 or 6)
            let version = (data[0] >> 4) & 0x0F;
            if version != 4 && version != 6 {
                return true;
            }
        }
        false
    }

    fn is_reconnaissance_attempt(&self, data: &[u8]) -> bool {
        // Detect port scanning and network reconnaissance
        data.len() == 0 || (data.len() < 50 && data.iter().all(|&b| b < 0x20))
    }

    pub fn disable_interface(&mut self, interface_id: u32) -> Result<(), &'static str> {
        if interface_id as usize >= self.interfaces.len() {
            return Err("Invalid interface ID");
        }

        self.interfaces[interface_id as usize].enabled.store(false, Ordering::Relaxed);
        crate::log::logger::log_info!("Network interface {} disabled", interface_id);
        Ok(())
    }

    pub fn enable_interface(&mut self, interface_id: u32) -> Result<(), &'static str> {
        if self.emergency_shutdown.load(Ordering::Relaxed) {
            return Err("Cannot enable interface during emergency shutdown");
        }

        if interface_id as usize >= self.interfaces.len() {
            return Err("Invalid interface ID");
        }

        self.interfaces[interface_id as usize].enabled.store(true, Ordering::Relaxed);
        crate::log::logger::log_info!("Network interface {} enabled", interface_id);
        Ok(())
    }

    pub fn emergency_shutdown(&mut self) {
        self.emergency_shutdown.store(true, Ordering::Relaxed);
        
        for interface in &self.interfaces {
            interface.enabled.store(false, Ordering::Relaxed);
        }

        crate::log::logger::log_info!("Emergency network shutdown completed - all interfaces disabled");
    }

    pub fn get_interface_statistics(&self, interface_id: u32) -> Option<NetworkStatistics> {
        if interface_id as usize >= self.interfaces.len() {
            return None;
        }

        let interface = &self.interfaces[interface_id as usize];
        
        Some(NetworkStatistics {
            interface_id: interface.interface_id,
            interface_name: interface.interface_name.clone(),
            packets_sent: interface.packets_sent.load(Ordering::Relaxed),
            packets_received: interface.packets_received.load(Ordering::Relaxed),
            bytes_sent: interface.bytes_sent.load(Ordering::Relaxed),
            bytes_received: interface.bytes_received.load(Ordering::Relaxed),
            enabled: interface.enabled.load(Ordering::Relaxed),
        })
    }
}

pub struct NetworkStatistics {
    pub interface_id: u32,
    pub interface_name: String,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub bytes_sent: u32,
    pub bytes_received: u32,
    pub enabled: bool,
}

static mut NETWORK_DRIVER: Option<NetworkDriver> = None;

pub fn init_network() {
    unsafe {
        NETWORK_DRIVER = Some(NetworkDriver::new());
    }
    crate::log::logger::log_info!("Network driver initialized");
}

pub fn register_ethernet_interface(name: String, mac: [u8; 6]) -> Result<u32, &'static str> {
    unsafe {
        if let Some(ref mut driver) = NETWORK_DRIVER {
            Ok(driver.register_interface(name, mac, InterfaceType::Ethernet))
        } else {
            Err("Network driver not initialized")
        }
    }
}

pub fn send_packet(interface_id: u32, data: &[u8], destination: &[u8; 6]) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref mut driver) = NETWORK_DRIVER {
            driver.send_packet(interface_id, data, destination)
        } else {
            Err("Network driver not initialized")
        }
    }
}

pub fn receive_packet(interface_id: u32) -> Result<Vec<u8>, &'static str> {
    unsafe {
        if let Some(ref mut driver) = NETWORK_DRIVER {
            driver.receive_packet(interface_id)
        } else {
            Err("Network driver not initialized")
        }
    }
}

pub fn emergency_disable_all() {
    unsafe {
        if let Some(ref mut driver) = NETWORK_DRIVER {
            driver.emergency_shutdown();
        }
    }
    crate::log::logger::log_info!("Emergency network shutdown executed");
}

pub fn get_network_statistics(interface_id: u32) -> Option<NetworkStatistics> {
    unsafe {
        if let Some(ref driver) = NETWORK_DRIVER {
            driver.get_interface_statistics(interface_id)
        } else {
            None
        }
    }
}

/// Send raw Ethernet frame via network interface (required by network layer)
pub fn send_ethernet_frame(interface_id: u32, frame: &[u8]) -> Result<(), &'static str> {
    if frame.len() < 14 {
        return Err("Frame too short - minimum 14 bytes for Ethernet header");
    }
    
    // Extract destination MAC from frame
    let dest_mac: [u8; 6] = [
        frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]
    ];
    
    // Extract payload (skip 14-byte Ethernet header)
    let payload = &frame[14..];
    
    // Use existing send_packet function
    send_packet(interface_id, payload, &dest_mac)
}