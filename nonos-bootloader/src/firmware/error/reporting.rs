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

use super::types::{FirmwareError, ErrorSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportingLevel { None, Minimal, Standard, Verbose, Debug }

#[derive(Debug, Clone)]
pub struct ErrorReport { error: FirmwareError, report_level: ReportingLevel, formatted_message: [u8; 512], report_id: u32 }

static mut ERROR_REPORTS: [Option<ErrorReport>; 64] = [None; 64];
static mut REPORT_COUNT: usize = 0;

pub fn report_error(error: FirmwareError, level: ReportingLevel) -> u32 {
    let report_id = generate_report_id();
    let formatted_message = format_error_message(&error, level);
    let report = ErrorReport { error, report_level: level, formatted_message, report_id };
    store_error_report(report);
    if should_escalate(&error) { escalate_error(&error); }
    report_id
}

pub fn format_error_message(error: &FirmwareError, level: ReportingLevel) -> [u8; 512] {
    let mut message = [0u8; 512];
    let formatted = match level {
        ReportingLevel::None => return message,
        ReportingLevel::Minimal => format_minimal(error),
        ReportingLevel::Standard => format_standard(error),
        ReportingLevel::Verbose => format_verbose(error),
        ReportingLevel::Debug => format_debug(error),
    };
    let bytes = formatted.as_bytes();
    let len = core::cmp::min(bytes.len(), 511);
    message[..len].copy_from_slice(&bytes[..len]);
    message
}

impl ErrorReport {
    pub fn get_formatted_message(&self) -> &str { let end = self.formatted_message.iter().position(|&b| b == 0).unwrap_or(512); core::str::from_utf8(&self.formatted_message[..end]).unwrap_or("invalid utf8") }
    pub fn get_severity(&self) -> ErrorSeverity { self.error.severity }
    pub fn get_id(&self) -> u32 { self.report_id }
}

fn generate_report_id() -> u32 { static mut NEXT_ID: u32 = 1; unsafe { NEXT_ID += 1; NEXT_ID - 1 } }
fn store_error_report(report: ErrorReport) { unsafe { if REPORT_COUNT < ERROR_REPORTS.len() { ERROR_REPORTS[REPORT_COUNT] = Some(report); REPORT_COUNT += 1; } } }
fn should_escalate(error: &FirmwareError) -> bool { matches!(error.severity, ErrorSeverity::Critical | ErrorSeverity::Fatal) }
fn escalate_error(_error: &FirmwareError) { }
fn format_minimal(error: &FirmwareError) -> alloc::string::String { alloc::format!("Error {}: {}", error.code, error.get_message()) }
fn format_standard(error: &FirmwareError) -> alloc::string::String { alloc::format!("[{:?}] Error {}: {} (firmware: {:?})", error.severity, error.code, error.get_message(), error.firmware_type) }
fn format_verbose(error: &FirmwareError) -> alloc::string::String { alloc::format!("[{:?}] {:?} Error {}: {} (firmware: {:?}, time: {})", error.severity, error.category, error.code, error.get_message(), error.firmware_type, error.timestamp) }
fn format_debug(error: &FirmwareError) -> alloc::string::String { alloc::format!("[{:?}] {:?} Error {}: {} (firmware: {:?}, time: {}, context: line {}, func {})", error.severity, error.category, error.code, error.get_message(), error.firmware_type, error.timestamp, error.context.file_line, error.context.function_id) }