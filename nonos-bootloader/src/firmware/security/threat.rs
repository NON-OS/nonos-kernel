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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel { None, Low, Medium, High, Critical }

#[derive(Debug, Clone)]
pub struct ThreatAnalysis { pub level: ThreatLevel, pub indicators: u32, pub confidence: u8, pub malware_signatures: u8 }

pub fn detect_threats(firmware_data: &[u8], vendor_id: u16) -> ThreatAnalysis {
    let mut indicators = 0;
    let mut malware_sigs = 0;
    if contains_suspicious_patterns(firmware_data) { indicators += 1; }
    if has_excessive_entropy(firmware_data) { indicators += 1; }
    if contains_known_malware_signatures(firmware_data) { malware_sigs += 1; indicators += 3; }
    if is_untrusted_vendor(vendor_id) { indicators += 2; }
    let level = match indicators { 0 => ThreatLevel::None, 1..=2 => ThreatLevel::Low, 3..=4 => ThreatLevel::Medium, 5..=7 => ThreatLevel::High, _ => ThreatLevel::Critical };
    let confidence = core::cmp::min(indicators * 15, 100) as u8;
    ThreatAnalysis { level, indicators, confidence, malware_signatures: malware_sigs }
}

pub fn analyze_firmware_behavior(execution_trace: &[u8]) -> ThreatLevel {
    let syscalls = count_syscalls(execution_trace);
    let network_access = count_network_operations(execution_trace);
    let file_access = count_file_operations(execution_trace);
    let risk_score = syscalls / 10 + network_access * 5 + file_access * 3;
    match risk_score { 0..=5 => ThreatLevel::Low, 6..=15 => ThreatLevel::Medium, 16..=30 => ThreatLevel::High, _ => ThreatLevel::Critical }
}

fn contains_suspicious_patterns(data: &[u8]) -> bool {
    data.windows(4).any(|w| matches!(w, b"exec" | b"fork" | b"kill" | b"root")) || data.windows(8).any(|w| w.iter().all(|&b| b >= 0x20 && b <= 0x7E))
}

fn has_excessive_entropy(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    let mut counts = [0u32; 256];
    for &byte in data { counts[byte as usize] += 1; }
    let unique_bytes = counts.iter().filter(|&&c| c > 0).count();
    unique_bytes > 200 && data.len() > 1024
}

fn contains_known_malware_signatures(data: &[u8]) -> bool {
    const SIGNATURES: &[&[u8]] = &[b"\x4d\x5a\x90\x00\x03\x00\x00\x00", b"\x7f\x45\x4c\x46\x02\x01\x01\x00", b"backdoor", b"rootkit"];
    SIGNATURES.iter().any(|sig| data.windows(sig.len()).any(|w| w == *sig))
}

fn is_untrusted_vendor(vendor_id: u16) -> bool { matches!(vendor_id, 0x0000 | 0xFFFF | 0x1234 | 0xDEAD | 0xBEEF) }
fn count_syscalls(trace: &[u8]) -> u32 { trace.windows(2).filter(|w| w == b"SC").count() as u32 }
fn count_network_operations(trace: &[u8]) -> u32 { trace.windows(3).filter(|w| w == b"NET").count() as u32 }
fn count_file_operations(trace: &[u8]) -> u32 { trace.windows(4).filter(|w| w == b"FILE").count() as u32 }