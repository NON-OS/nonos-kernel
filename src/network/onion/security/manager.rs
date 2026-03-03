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


use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use crate::network::onion::{OnionError, CircuitId};
use crate::crypto::{vault, entropy};

use super::types::{RateLimiter, TimingAttackDetector, MemoryProtector, SecurityStats};

pub(crate) struct SecurityManager {
    rate_limiters: Mutex<BTreeMap<[u8; 4], RateLimiter>>,
    circuit_counters: Mutex<BTreeMap<[u8; 4], u32>>,
    timing_detector: TimingAttackDetector,
    memory_protector: MemoryProtector,
    stats: SecurityStats,
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
        let current_time = get_timestamp();
        let mut limiters = self.rate_limiters.lock();

        let limiter = limiters.entry(client_ip).or_insert_with(|| RateLimiter {
            ip: client_ip,
            cells_this_second: AtomicU32::new(0),
            last_reset: AtomicU64::new(current_time),
            violations: AtomicU32::new(0),
        });

        let last_reset = limiter.last_reset.load(Ordering::Relaxed);
        if current_time - last_reset >= 1000 {
            limiter.cells_this_second.store(0, Ordering::Relaxed);
            limiter.last_reset.store(current_time, Ordering::Relaxed);
        }

        let current_count = limiter.cells_this_second.fetch_add(1, Ordering::Relaxed);
        if current_count > 1000 {
            limiter.violations.fetch_add(1, Ordering::Relaxed);
            self.stats.rate_limit_violations.fetch_add(1, Ordering::Relaxed);

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

        if current_count >= 100 {
            self.stats.blocked_ips.fetch_add(1, Ordering::Relaxed);
            return Err(OnionError::SecurityViolation);
        }

        counters.insert(client_ip, current_count + 1);
        Ok(())
    }

    pub fn detect_timing_attack(&self, circuit_id: CircuitId) -> Result<(), OnionError> {
        let current_time = get_timestamp();
        let mut timings = self.timing_detector.cell_timings.lock();

        let circuit_timings = timings.entry(circuit_id).or_insert_with(Vec::new);
        circuit_timings.push(current_time);

        if circuit_timings.len() > 100 {
            circuit_timings.remove(0);
        }

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

        let mut intervals = Vec::new();
        for i in 1..timings.len() {
            intervals.push((timings[i] - timings[i-1]) as f32);
        }

        let mean = intervals.iter().sum::<f32>() / intervals.len() as f32;
        let variance = intervals.iter()
            .map(|x| { let diff = x - mean; diff * diff })
            .sum::<f32>() / intervals.len() as f32;

        if variance < 100.0 {
            0.8
        } else {
            variance / 10000.0
        }
    }

    pub fn secure_allocate(&self, size: usize) -> Result<*mut u8, OnionError> {
        let total_size = size + 16;
        let raw_ptr = vault::allocate_secure_memory(total_size);

        let canary = self.memory_protector.generate_canary();
        unsafe {
            core::ptr::write(raw_ptr as *mut u64, canary);
            core::ptr::write((raw_ptr as *mut u64).add(1 + size / 8), canary);
        }

        let user_ptr = unsafe { (raw_ptr as *mut u8).add(8) };

        let alloc_info = super::types::AllocInfo {
            size,
            canary,
            allocated_at: get_timestamp(),
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

        let raw_ptr = unsafe { ptr.sub(8) };
        unsafe {
            let front_canary = core::ptr::read(raw_ptr as *const u64);
            let back_canary = core::ptr::read((raw_ptr as *const u64).add(1 + size / 8));

            if front_canary != alloc_info.canary || back_canary != alloc_info.canary {
                self.stats.memory_violations.fetch_add(1, Ordering::Relaxed);
                return Err(OnionError::SecurityViolation);
            }
        }

        unsafe {
            core::ptr::write_bytes(ptr, 0, size);
        }

        vault::deallocate_secure_memory(raw_ptr, alloc_info.size);

        Ok(())
    }

    pub fn sanitize_buffer(&self, buffer: &mut [u8]) {
        let _ = entropy::fill_random(buffer);
        buffer.fill(0);
        let _ = entropy::fill_random(buffer);
        buffer.fill(0);
    }
}

pub(super) fn get_timestamp() -> u64 {
    crate::arch::x86_64::time::timer::get_timestamp_ms().unwrap_or(0)
}

static SECURITY_MANAGER: Mutex<Option<SecurityManager>> = Mutex::new(None);

pub fn init_security() -> Result<(), OnionError> {
    let manager = SecurityManager::new();
    *SECURITY_MANAGER.lock() = Some(manager);
    Ok(())
}

pub(crate) fn get_security_manager() -> &'static Mutex<Option<SecurityManager>> {
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

pub(crate) fn secure_zero(data: &mut [u8]) {
    if let Some(manager) = SECURITY_MANAGER.lock().as_ref() {
        manager.sanitize_buffer(data);
    } else {
        data.fill(0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
