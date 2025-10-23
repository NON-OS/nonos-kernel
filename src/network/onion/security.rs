//! NONOS-Security for Onion Routing Integration
//!
//! Security using NONOS crypto infrastructure

use alloc::{vec::Vec, collections::BTreeMap, vec};
use spin::Mutex;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::{OnionError, CircuitId};
use super::cell::Cell;
use crate::crypto::{hash, vault, entropy};

/// Security manager with actual threat detection
pub struct SecurityManager {
    rate_limiters: Mutex<BTreeMap<[u8; 4], RateLimiter>>,
    circuit_counters: Mutex<BTreeMap<[u8; 4], u32>>,
    timing_detector: TimingAttackDetector,
    memory_protector: MemoryProtector,
    stats: SecurityStats,
}

struct RateLimiter {
    ip: [u8; 4],
    cells_this_second: AtomicU32,
    last_reset: AtomicU64,
    violations: AtomicU32,
}

struct TimingAttackDetector {
    cell_timings: Mutex<BTreeMap<CircuitId, Vec<u64>>>,
    correlation_threshold: f32,
}

struct MemoryProtector {
    allocations: Mutex<BTreeMap<usize, AllocInfo>>,
    canary_seed: u64,
}

struct AllocInfo {
    size: usize,
    canary: u64,
    allocated_at: u64,
}

struct SecurityStats {
    blocked_ips: AtomicU32,
    timing_attacks_detected: AtomicU32,
    rate_limit_violations: AtomicU32,
    memory_violations: AtomicU32,
}

impl SecurityManager {
    pub fn new() -> Self {
        SecurityManager {
            rate_limiters: Mutex::new(BTreeMap::new()),
            circuit_counters: Mutex::new(BTreeMap::new()),
            timing_detector: TimingAttackDetector::new(),
            memory_protector: MemoryProtector::new(),
            stats: SecurityStats::new(),
        }
    }

    pub fn check_client_rate_limit(&self, client_ip: [u8; 4]) -> Result<(), OnionError> {
        let current_time = Self::get_timestamp();
        let mut limiters = self.rate_limiters.lock();
        
        let limiter = limiters.entry(client_ip).or_insert_with(|| RateLimiter {
            ip: client_ip,
            cells_this_second: AtomicU32::new(0),
            last_reset: AtomicU64::new(current_time),
            violations: AtomicU32::new(0),
        });

        // Reset counter every second
        let last_reset = limiter.last_reset.load(Ordering::Relaxed);
        if current_time - last_reset >= 1000 {
            limiter.cells_this_second.store(0, Ordering::Relaxed);
            limiter.last_reset.store(current_time, Ordering::Relaxed);
        }

        // Check rate limit (1000 cells per second max)
        let current_count = limiter.cells_this_second.fetch_add(1, Ordering::Relaxed);
        if current_count > 1000 {
            limiter.violations.fetch_add(1, Ordering::Relaxed);
            self.stats.rate_limit_violations.fetch_add(1, Ordering::Relaxed);
            
            // Block IP after 3 violations
            if limiter.violations.load(Ordering::Relaxed) > 3 {
                self.stats.blocked_ips.fetch_add(1, Ordering::Relaxed);
                return Err(OnionError::SecurityViolation);
            }
            
            return Err(OnionError::NetworkError);
        }

        Ok(())
    }

    pub fn check_circuit_limit(&self, client_ip: [u8; 4]) -> Result<(), OnionError> {
        let mut counters = self.circuit_counters.lock();
        let current_count = counters.get(&client_ip).copied().unwrap_or(0);
        
        // Max 100 circuits per IP
        if current_count >= 100 {
            self.stats.blocked_ips.fetch_add(1, Ordering::Relaxed);
            return Err(OnionError::SecurityViolation);
        }
        
        counters.insert(client_ip, current_count + 1);
        Ok(())
    }

    pub fn detect_timing_attack(&self, circuit_id: CircuitId) -> Result<(), OnionError> {
        let current_time = Self::get_timestamp();
        let mut timings = self.timing_detector.cell_timings.lock();
        
        let circuit_timings = timings.entry(circuit_id).or_insert_with(Vec::new);
        circuit_timings.push(current_time);
        
        // Keep only last 100 timings
        if circuit_timings.len() > 100 {
            circuit_timings.remove(0);
        }
        
        // Detect regular patterns (simplified correlation analysis)
        if circuit_timings.len() >= 10 {
            let correlation = self.calculate_timing_correlation(circuit_timings);
            if correlation > self.timing_detector.correlation_threshold {
                self.stats.timing_attacks_detected.fetch_add(1, Ordering::Relaxed);
                return Err(OnionError::SecurityViolation);
            }
        }
        
        Ok(())
    }

    fn calculate_timing_correlation(&self, timings: &[u64]) -> f32 {
        if timings.len() < 2 {
            return 0.0;
        }
        
        // Calculate intervals between timings
        let mut intervals = Vec::new();
        for i in 1..timings.len() {
            intervals.push((timings[i] - timings[i-1]) as f32);
        }
        
        // Calculate variance - low variance indicates regular timing
        let mean = intervals.iter().sum::<f32>() / intervals.len() as f32;
        let variance = intervals.iter()
            .map(|x| { let diff = x - mean; diff * diff })
            .sum::<f32>() / intervals.len() as f32;
        
        // High correlation if variance is very low
        if variance < 100.0 { // Less than 100ms variance
            0.8 // High correlation score
        } else {
            variance / 10000.0 // Normalize variance to 0-1 range
        }
    }

    pub fn secure_allocate(&self, size: usize) -> Result<*mut u8, OnionError> {
        // Allocate with guard pages
        let total_size = size + 16; // 8 bytes before + 8 bytes after
        let mut raw_ptr = vault::allocate_secure_memory(total_size);
        
        // Add canary values
        let canary = self.memory_protector.generate_canary();
        unsafe {
            core::ptr::write(raw_ptr as *mut u64, canary);
            core::ptr::write((raw_ptr as *mut u64).add(1 + size / 8), canary);
        }
        
        let user_ptr = unsafe { (raw_ptr as *mut u8).add(8) };
        
        // Store allocation info
        let alloc_info = AllocInfo {
            size,
            canary,
            allocated_at: Self::get_timestamp(),
        };
        
        self.memory_protector.allocations.lock().insert(user_ptr as usize, alloc_info);
        
        Ok(user_ptr)
    }

    pub fn secure_deallocate(&self, ptr: *mut u8, size: usize) -> Result<(), OnionError> {
        let mut allocations = self.memory_protector.allocations.lock();
        let alloc_info = allocations.remove(&(ptr as usize))
            .ok_or(OnionError::CryptoError)?;
        
        if alloc_info.size != size {
            self.stats.memory_violations.fetch_add(1, Ordering::Relaxed);
            return Err(OnionError::SecurityViolation);
        }
        
        // Check canaries
        let raw_ptr = unsafe { ptr.sub(8) };
        unsafe {
            let front_canary = core::ptr::read(raw_ptr as *const u64);
            let back_canary = core::ptr::read((raw_ptr as *const u64).add(1 + size / 8));
            
            if front_canary != alloc_info.canary || back_canary != alloc_info.canary {
                self.stats.memory_violations.fetch_add(1, Ordering::Relaxed);
                return Err(OnionError::SecurityViolation);
            }
        }
        
        // Zero memory before freeing
        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }
        
        // Deallocate secure memory
        vault::deallocate_secure_memory(raw_ptr, alloc_info.size);
        
        Ok(())
    }

    pub fn sanitize_buffer(&self, buffer: &mut [u8]) {
        // Overwrite with cryptographically secure random data
        entropy::fill_random(buffer);
        
        // Second pass with zeros
        buffer.fill(0);
        
        // Third pass with random again
        entropy::fill_random(buffer);
        
        // Final zero
        buffer.fill(0);
    }

    pub fn add_circuit_padding(&self, circuit_id: CircuitId) -> Result<Vec<Cell>, OnionError> {
        // Generate 1-5 padding cells
        let num_padding = (entropy::rand_u32() % 5) + 1;
        let mut padding_cells = Vec::new();
        
        for _ in 0..num_padding {
            let mut padding_data = vec![0u8; 509];
            entropy::fill_random(&mut padding_data);
            
            let padding_cell = Cell::new(
                circuit_id, 
                super::cell::CellType::Padding, 
                padding_data
            );
            
            padding_cells.push(padding_cell);
        }
        
        Ok(padding_cells)
    }

    pub fn constant_time_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for i in 0..a.len() {
            result |= a[i] ^ b[i];
        }
        
        result == 0
    }

    pub fn get_security_stats(&self) -> &SecurityStats {
        &self.stats
    }

    fn get_timestamp() -> u64 {
        crate::arch::x86_64::time::timer::get_timestamp_ms().unwrap_or(0)
    }
}

impl TimingAttackDetector {
    fn new() -> Self {
        TimingAttackDetector {
            cell_timings: Mutex::new(BTreeMap::new()),
            correlation_threshold: 0.7, // 70% correlation threshold
        }
    }
}

impl MemoryProtector {
    fn new() -> Self {
        MemoryProtector {
            allocations: Mutex::new(BTreeMap::new()),
            canary_seed: entropy::rand_u64(),
        }
    }
    
    fn generate_canary(&self) -> u64 {
        // Generate unique canary for each allocation  
        let mut data = Vec::new();
        data.extend_from_slice(&self.canary_seed.to_le_bytes());
        data.extend_from_slice(&entropy::rand_u64().to_le_bytes());
        data.extend_from_slice(&SecurityManager::get_timestamp().to_le_bytes());
        hash::blake3_hash(&data)[..8].try_into()
            .map(u64::from_le_bytes)
            .unwrap_or(0xDEADBEEFCAFEBABE)
    }
}

impl SecurityStats {
    fn new() -> Self {
        SecurityStats {
            blocked_ips: AtomicU32::new(0),
            timing_attacks_detected: AtomicU32::new(0),
            rate_limit_violations: AtomicU32::new(0),
            memory_violations: AtomicU32::new(0),
        }
    }
    
    pub fn get_blocked_ips(&self) -> u32 {
        self.blocked_ips.load(Ordering::Relaxed)
    }
    
    pub fn get_timing_attacks(&self) -> u32 {
        self.timing_attacks_detected.load(Ordering::Relaxed)
    }
    
    pub fn get_rate_violations(&self) -> u32 {
        self.rate_limit_violations.load(Ordering::Relaxed)
    }
    
    pub fn get_memory_violations(&self) -> u32 {
        self.memory_violations.load(Ordering::Relaxed)
    }
}

/// Constant-time operations for cryptographic safety
pub struct ConstantTime;

impl ConstantTime {
    pub fn select_u8(condition: u8, true_val: u8, false_val: u8) -> u8 {
        let mask = condition.wrapping_sub(1);
        (true_val & !mask) | (false_val & mask)
    }
    
    pub fn select_u32(condition: u32, true_val: u32, false_val: u32) -> u32 {
        let mask = condition.wrapping_sub(1);
        (true_val & !mask) | (false_val & mask)
    }
    
    pub fn is_zero(value: u8) -> u8 {
        let mut result = value;
        result |= result >> 4;
        result |= result >> 2;
        result |= result >> 1;
        (result ^ 1) & 1
    }
    
    pub fn conditional_copy(condition: u8, dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        let mask = condition.wrapping_sub(1);
        
        for i in 0..dst.len() {
            dst[i] = (src[i] & !mask) | (dst[i] & mask);
        }
    }
}

/// Secure random number generation for security
pub struct SecureRandom;

impl SecureRandom {
    pub fn generate_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        entropy::fill_random(&mut nonce);
        nonce
    }
    
    pub fn generate_session_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        entropy::fill_random(&mut key);
        key
    }
    
    pub fn generate_circuit_id() -> u32 {
        // Ensure circuit ID is not zero and has entropy
        loop {
            let id = entropy::rand_u32();
            if id != 0 {
                return id;
            }
        }
    }
    
    pub fn timing_jitter_ms() -> u32 {
        // Random jitter 0-50ms for timing attack resistance
        entropy::rand_u32() % 50
    }
}

/// Network-level protections
pub struct NetworkSecurity;

impl NetworkSecurity {
    pub fn validate_cell_structure(cell: &Cell) -> Result<(), OnionError> {
        // Check cell size
        if cell.payload.len() > 509 {
            return Err(OnionError::InvalidCell);
        }
        
        // Check circuit ID is not zero
        if cell.circuit_id == 0 {
            return Err(OnionError::InvalidCell);
        }
        
        // Basic command validation
        match cell.command {
            0..=15 | 128..=132 => Ok(()),
            _ => Err(OnionError::InvalidCell),
        }
    }
    
    pub fn check_connection_limits(active_connections: u32) -> Result<(), OnionError> {
        const MAX_CONNECTIONS: u32 = 10000;
        
        if active_connections > MAX_CONNECTIONS {
            return Err(OnionError::NetworkError);
        }
        
        Ok(())
    }
    
    pub fn validate_handshake_timing(start_time: u64, end_time: u64) -> Result<(), OnionError> {
        let duration = end_time - start_time;
        
        // Handshake should take between 100ms and 30 seconds
        if duration < 100 || duration > 30000 {
            return Err(OnionError::SecurityViolation);
        }
        
        Ok(())
    }
}

/// Global security configuration
static SECURITY_MANAGER: Mutex<Option<SecurityManager>> = Mutex::new(None);

pub fn init_security() -> Result<(), OnionError> {
    let manager = SecurityManager::new();
    *SECURITY_MANAGER.lock() = Some(manager);
    Ok(())
}

pub fn get_security_manager() -> &'static Mutex<Option<SecurityManager>> {
    &SECURITY_MANAGER
}

pub fn check_client_security(client_ip: [u8; 4], circuit_id: CircuitId) -> Result<(), OnionError> {
    if let Some(manager) = SECURITY_MANAGER.lock().as_ref() {
        manager.check_client_rate_limit(client_ip)?;
        manager.check_circuit_limit(client_ip)?;
        manager.detect_timing_attack(circuit_id)?;
    }
    Ok(())
}

pub fn secure_zero(data: &mut [u8]) {
    if let Some(manager) = SECURITY_MANAGER.lock().as_ref() {
        manager.sanitize_buffer(data);
    } else {
        // Fallback secure zero
        data.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}