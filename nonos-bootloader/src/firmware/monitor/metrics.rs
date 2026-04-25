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

#![allow(static_mut_refs)]

use crate::firmware::types::FirmwareType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType { Counter, Gauge, Histogram, Timer }

#[derive(Clone, Copy)]
pub enum MetricValue { Counter(u64), Gauge(i64), Timer(u64) }

#[derive(Debug, Clone, Copy)]
pub struct FirmwareMetrics { firmware_type: FirmwareType, counters: [u64; 8], gauges: [i64; 8], last_update: u64 }

static mut GLOBAL_METRICS: [FirmwareMetrics; 32] = [const { FirmwareMetrics::empty() }; 32];
static mut METRICS_COUNT: usize = 0;

pub fn collect_metrics(firmware_type: FirmwareType) -> Option<&'static FirmwareMetrics> {
    unsafe { GLOBAL_METRICS.iter().find(|m| m.firmware_type == firmware_type && m.last_update > 0) }
}

pub fn update_metric(firmware_type: FirmwareType, name: &str, metric_type: MetricType, value: u64) -> bool {
    let index = hash_name(name) % 8;
    unsafe {
        if let Some(metrics) = GLOBAL_METRICS.iter_mut().find(|m| m.firmware_type == firmware_type) {
            match metric_type { MetricType::Counter => metrics.counters[index] = value, MetricType::Gauge => metrics.gauges[index] = value as i64, _ => metrics.counters[index] = value }
            metrics.last_update = get_timestamp();
            return true;
        }
        if METRICS_COUNT < GLOBAL_METRICS.len() {
            let mut new_metrics = FirmwareMetrics::new(firmware_type);
            match metric_type { MetricType::Counter => new_metrics.counters[index] = value, MetricType::Gauge => new_metrics.gauges[index] = value as i64, _ => new_metrics.counters[index] = value }
            GLOBAL_METRICS[METRICS_COUNT] = new_metrics;
            METRICS_COUNT += 1;
            return true;
        }
    }
    false
}

impl FirmwareMetrics {
    const fn empty() -> Self { Self { firmware_type: FirmwareType::Unknown, counters: [0; 8], gauges: [0; 8], last_update: 0 } }
    fn new(firmware_type: FirmwareType) -> Self { Self { firmware_type, counters: [0; 8], gauges: [0; 8], last_update: get_timestamp() } }
    pub fn get_counter(&self, index: usize) -> u64 { if index < 8 { self.counters[index] } else { 0 } }
    pub fn get_gauge(&self, index: usize) -> i64 { if index < 8 { self.gauges[index] } else { 0 } }
}

fn get_timestamp() -> u64 { static mut COUNTER: u64 = 0; unsafe { COUNTER += 1; COUNTER } }
fn hash_name(name: &str) -> usize { name.bytes().fold(0usize, |acc, b| acc.wrapping_add(b as usize)) }