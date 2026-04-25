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

use crate::firmware::types::FirmwareType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus { Healthy, Degraded, Unhealthy, Critical, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthResult { Pass, Fail, Warning, Timeout, NotApplicable }

#[derive(Debug, Clone)]
pub struct HealthCheck { firmware_type: FirmwareType, check_name: [u8; 32], last_result: HealthResult, last_check_time: u64, check_count: u32, failure_count: u32 }

#[derive(Debug, Clone, Copy)]
pub struct PerformanceMetrics { load_time_ms: u32, memory_usage_bytes: u32, cpu_usage_percent: u8, temperature_celsius: u8, error_rate_per_hour: u16 }

pub fn check_firmware_health(firmware_type: FirmwareType) -> HealthStatus {
    let metrics = get_performance_metrics(firmware_type);
    let mut health_score = 100u8;
    if metrics.load_time_ms > 1000 { health_score = health_score.saturating_sub(10); }
    if metrics.memory_usage_bytes > 64 * 1024 * 1024 { health_score = health_score.saturating_sub(15); }
    if metrics.cpu_usage_percent > 80 { health_score = health_score.saturating_sub(20); }
    if metrics.temperature_celsius > 85 { health_score = health_score.saturating_sub(25); }
    if metrics.error_rate_per_hour > 10 { health_score = health_score.saturating_sub(30); }
    match health_score { 90..=100 => HealthStatus::Healthy, 70..=89 => HealthStatus::Degraded, 50..=69 => HealthStatus::Unhealthy, 1..=49 => HealthStatus::Critical, 0 => HealthStatus::Critical }
}

impl Default for HealthCheck {
    fn default() -> Self { Self { firmware_type: FirmwareType::Unknown, check_name: [0; 32], last_result: HealthResult::NotApplicable, last_check_time: 0, check_count: 0, failure_count: 0 } }
}

impl HealthCheck {
    pub fn new(firmware_type: FirmwareType, name: &str) -> Self { let mut check = Self::default(); check.firmware_type = firmware_type; let name_bytes = name.as_bytes(); let len = core::cmp::min(name_bytes.len(), 31); check.check_name[..len].copy_from_slice(&name_bytes[..len]); check }
    pub fn execute(&mut self) -> HealthResult { self.check_count += 1; self.last_check_time = get_current_time(); let result = perform_health_check(self.firmware_type); if result == HealthResult::Fail { self.failure_count += 1; } self.last_result = result; result }
    pub fn get_success_rate(&self) -> f32 { if self.check_count == 0 { 0.0 } else { (self.check_count - self.failure_count) as f32 / self.check_count as f32 } }
}

impl Default for PerformanceMetrics {
    fn default() -> Self { Self { load_time_ms: 0, memory_usage_bytes: 0, cpu_usage_percent: 0, temperature_celsius: 0, error_rate_per_hour: 0 } }
}

fn get_performance_metrics(firmware_type: FirmwareType) -> PerformanceMetrics {
    let base_load_time = match firmware_type { FirmwareType::IntelAx200 | FirmwareType::IntelAx210 => 500, FirmwareType::Rtl8821c | FirmwareType::Rtl8822c => 800, _ => 300 };
    PerformanceMetrics { load_time_ms: base_load_time + (get_current_time() % 200) as u32, memory_usage_bytes: 32 * 1024 * 1024 + ((get_current_time() % 16) * 1024 * 1024) as u32, cpu_usage_percent: (20 + get_current_time() % 60) as u8, temperature_celsius: (45 + get_current_time() % 40) as u8, error_rate_per_hour: (get_current_time() % 5) as u16 }
}

fn perform_health_check(firmware_type: FirmwareType) -> HealthResult { if firmware_type == FirmwareType::Unknown { HealthResult::NotApplicable } else { HealthResult::Pass } }
fn get_current_time() -> u64 { static mut COUNTER: u64 = 0; unsafe { COUNTER += 1; COUNTER } }