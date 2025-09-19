//! System Health Monitoring
//! 
//! Simple, reliable system monitoring for production use

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::memory::heap;
use crate::time;

/// System health status
#[derive(Debug, Clone, Copy)]
pub struct SystemHealth {
    pub heap_usage_percent: u8,
    pub heap_failures: u64,
    pub uptime_seconds: u64,
    pub is_healthy: bool,
}

/// Global system statistics
static BOOT_TIME: AtomicU64 = AtomicU64::new(0);
static HEALTH_CHECKS: AtomicU64 = AtomicU64::new(0);
static LAST_HEALTH_CHECK: AtomicU64 = AtomicU64::new(0);
static SYSTEM_STABLE: AtomicBool = AtomicBool::new(true);

/// Initialize monitoring system
pub fn init() {
    let boot_timestamp = time::timestamp_millis();
    BOOT_TIME.store(boot_timestamp, Ordering::SeqCst);
    LAST_HEALTH_CHECK.store(boot_timestamp, Ordering::SeqCst);
    SYSTEM_STABLE.store(true, Ordering::SeqCst);
}

/// Get current system health snapshot
pub fn get_system_health() -> SystemHealth {
    HEALTH_CHECKS.fetch_add(1, Ordering::Relaxed);
    
    let heap_stats = heap::get_heap_stats();
    let current_time = time::timestamp_millis();
    let boot_time = BOOT_TIME.load(Ordering::SeqCst);
    
    // Calculate heap usage percentage
    let heap_usage_percent = if heap_stats.total_size > 0 {
        ((heap_stats.current_usage * 100) / heap_stats.total_size).min(100) as u8
    } else {
        0
    };
    
    // Calculate uptime
    let uptime_seconds = (current_time - boot_time) / 1000;
    
    // Determine if system is healthy
    let is_healthy = heap_stats.enabled &&
        heap_usage_percent < 90 &&
        heap_stats.failures < heap_stats.allocations / 20 &&  // Less than 5% failure rate
        SYSTEM_STABLE.load(Ordering::Relaxed);
    
    LAST_HEALTH_CHECK.store(current_time, Ordering::SeqCst);
    
    SystemHealth {
        heap_usage_percent,
        heap_failures: heap_stats.failures,
        uptime_seconds,
        is_healthy,
    }
}

/// Mark system as unstable due to critical error
pub fn mark_system_unstable() {
    SYSTEM_STABLE.store(false, Ordering::SeqCst);
}

/// Check if system is stable (for use by panic handler)
pub fn is_system_stable() -> bool {
    SYSTEM_STABLE.load(Ordering::SeqCst)
}

/// Get basic system statistics
pub fn get_basic_stats() -> (u64, u64, u64) {
    (
        HEALTH_CHECKS.load(Ordering::Relaxed),
        LAST_HEALTH_CHECK.load(Ordering::Relaxed),
        BOOT_TIME.load(Ordering::SeqCst),
    )
}

/// Periodic health check function (call from scheduler)
pub fn periodic_health_check() {
    let health = get_system_health();
    
    // Log warnings for concerning conditions
    if health.heap_usage_percent > 75 {
        crate::log::logger::log_critical("High heap usage detected");
    }
    
    if health.heap_failures > 10 {
        crate::log::logger::log_critical("Multiple heap allocation failures");
    }
    
    if !health.is_healthy {
        crate::log::logger::log_critical("System health check failed");
    }
}

/// Update system metrics (called from main loop)
pub fn update_metrics() {
    periodic_health_check();
}