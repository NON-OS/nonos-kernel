use crate::security::data_leak_detection::{monitor_file_access, DataLeakEvent, FileOperation};
use alloc::{format, string::String, vec, vec::Vec};

#[derive(Clone)]
pub struct ImageData {
    pub data: Vec<u8>,
}

pub struct ClipboardManager {
    clipboard_data: Vec<ClipboardEntry>,
    max_entries: usize,
    encryption_enabled: bool,
    monitoring_enabled: bool,
    access_log: Vec<ClipboardAccess>,
}

#[derive(Clone)]
pub struct ClipboardEntry {
    data: Vec<u8>,
    format: ClipboardFormat,
    timestamp: u64,
    source_process: u32,
    sensitivity_level: u8,
    encrypted: bool,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ClipboardFormat {
    Text = 1,
    Html = 2,
    Image = 3,
    Audio = 4,
    Video = 5,
    File = 6,
    Binary = 7,
    Rtf = 8,
    Csv = 9,
    Json = 10,
    RichText = 11,
    Files = 12,
}

#[derive(Clone)]
pub struct ClipboardAccess {
    process_id: u32,
    access_type: AccessType,
    timestamp: u64,
    data_size: usize,
    format: ClipboardFormat,
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum AccessType {
    Read = 1,
    Write = 2,
    Clear = 3,
    Query = 4,
}

pub struct ClipboardSecurity {
    blocked_processes: Vec<u32>,
    allowed_formats: Vec<ClipboardFormat>,
    max_data_size: usize,
    cross_process_enabled: bool,
    leak_detection_enabled: bool,
}

pub struct ClipboardStatistics {
    pub total_operations: usize,
    pub blocked_operations: usize,
    pub data_leaks_detected: usize,
    pub active_entries: usize,
    pub memory_usage: usize,
}

impl ClipboardManager {
    pub fn new() -> Self {
        ClipboardManager {
            clipboard_data: Vec::new(),
            max_entries: 100,
            encryption_enabled: true,
            monitoring_enabled: true,
            access_log: Vec::new(),
        }
    }

    pub fn copy_data(
        &mut self,
        data: &[u8],
        format: ClipboardFormat,
        source_process: u32,
    ) -> Result<(), &'static str> {
        if data.is_empty() {
            return Err("Empty data cannot be copied to clipboard");
        }

        if data.len() > 16 * 1024 * 1024 {
            return Err("Data too large for clipboard");
        }

        let sensitivity = self.analyze_data_sensitivity(data);

        if self.monitoring_enabled {
            if let Some(_leak_event) = monitor_file_access("clipboard", data, FileOperation::Write)
            {
                return Err("Potential data leak detected in clipboard operation");
            }
        }

        let encrypted_data = if self.encryption_enabled && sensitivity > 5 {
            self.encrypt_clipboard_data(data)?
        } else {
            data.to_vec()
        };

        let entry = ClipboardEntry {
            data: encrypted_data,
            format,
            timestamp: crate::time::get_timestamp(),
            source_process,
            sensitivity_level: sensitivity,
            encrypted: self.encryption_enabled && sensitivity > 5,
        };

        if self.clipboard_data.len() >= self.max_entries {
            self.clipboard_data.remove(0);
        }

        self.clipboard_data.push(entry);

        self.log_access(source_process, AccessType::Write, data.len(), format);

        Ok(())
    }

    pub fn paste_data(
        &mut self,
        requesting_process: u32,
        format_filter: Option<ClipboardFormat>,
    ) -> Result<Vec<u8>, &'static str> {
        if self.clipboard_data.is_empty() {
            return Err("Clipboard is empty");
        }

        let latest_entry = &self.clipboard_data[self.clipboard_data.len() - 1];

        if let Some(filter) = format_filter {
            if latest_entry.format != filter {
                return Err("Clipboard data format does not match filter");
            }
        }

        if !self.can_access_clipboard(requesting_process) {
            return Err("Process not authorized to access clipboard");
        }

        let decrypted_data = if latest_entry.encrypted {
            self.decrypt_clipboard_data(&latest_entry.data)?
        } else {
            latest_entry.data.clone()
        };

        self.log_access(
            requesting_process,
            AccessType::Read,
            decrypted_data.len(),
            latest_entry.format,
        );

        Ok(decrypted_data)
    }

    fn analyze_data_sensitivity(&self, data: &[u8]) -> u8 {
        let mut sensitivity = 1u8;

        if self.contains_pattern(data, b"password") || self.contains_pattern(data, b"secret") {
            sensitivity = sensitivity.max(9);
        }

        if self.contains_pattern(data, b"BEGIN PRIVATE KEY")
            || self.contains_pattern(data, b"BEGIN RSA PRIVATE KEY")
        {
            sensitivity = sensitivity.max(10);
        }

        if self.contains_credit_card_pattern(data) {
            sensitivity = sensitivity.max(8);
        }

        if self.contains_ssn_pattern(data) {
            sensitivity = sensitivity.max(9);
        }

        if data.len() > 1024 * 1024 {
            sensitivity = sensitivity.max(6);
        }

        sensitivity
    }

    fn contains_pattern(&self, data: &[u8], pattern: &[u8]) -> bool {
        if pattern.len() > data.len() {
            return false;
        }

        for i in 0..=(data.len() - pattern.len()) {
            if data[i..i + pattern.len()].eq_ignore_ascii_case(pattern) {
                return true;
            }
        }
        false
    }

    fn contains_credit_card_pattern(&self, data: &[u8]) -> bool {
        let mut consecutive_digits = 0;
        for &byte in data {
            if byte.is_ascii_digit() {
                consecutive_digits += 1;
                if consecutive_digits >= 13 {
                    return true;
                }
            } else if byte != b' ' && byte != b'-' {
                consecutive_digits = 0;
            }
        }
        false
    }

    fn contains_ssn_pattern(&self, data: &[u8]) -> bool {
        let text = core::str::from_utf8(data).unwrap_or("");
        text.len() >= 9 && text.chars().filter(|c| c.is_ascii_digit()).count() >= 9
    }

    fn encrypt_clipboard_data(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key = self.get_encryption_key();
        let mut encrypted = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            encrypted.push(byte ^ key[i % key.len()]);
        }

        Ok(encrypted)
    }

    fn decrypt_clipboard_data(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.encrypt_clipboard_data(data)
    }

    fn get_encryption_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        let timestamp = crate::time::get_timestamp();

        for i in 0..32 {
            key[i] = ((timestamp >> (i % 8)) ^ (i as u64 * 31)) as u8;
        }

        key
    }

    fn can_access_clipboard(&self, process_id: u32) -> bool {
        true
    }

    fn log_access(
        &mut self,
        process_id: u32,
        access_type: AccessType,
        data_size: usize,
        format: ClipboardFormat,
    ) {
        if !self.monitoring_enabled {
            return;
        }

        let access = ClipboardAccess {
            process_id,
            access_type,
            timestamp: crate::time::get_timestamp(),
            data_size,
            format,
        };

        self.access_log.push(access);

        if self.access_log.len() > 1000 {
            self.access_log.remove(0);
        }
    }

    pub fn clear_clipboard(&mut self, requesting_process: u32) -> Result<(), &'static str> {
        if !self.can_access_clipboard(requesting_process) {
            return Err("Process not authorized to clear clipboard");
        }

        self.clipboard_data.clear();
        self.log_access(requesting_process, AccessType::Clear, 0, ClipboardFormat::Text);

        Ok(())
    }

    pub fn get_available_formats(&self) -> Vec<ClipboardFormat> {
        self.clipboard_data.iter().map(|entry| entry.format).collect()
    }

    pub fn get_clipboard_statistics(&self) -> ClipboardStatistics {
        let total_operations = self.access_log.len();
        let memory_usage = self.clipboard_data.iter().map(|entry| entry.data.len()).sum::<usize>();

        ClipboardStatistics {
            total_operations,
            blocked_operations: 0,
            data_leaks_detected: 0,
            active_entries: self.clipboard_data.len(),
            memory_usage,
        }
    }

    pub fn enable_encryption(&mut self) {
        self.encryption_enabled = true;
    }

    pub fn disable_encryption(&mut self) {
        self.encryption_enabled = false;
    }

    pub fn enable_monitoring(&mut self) {
        self.monitoring_enabled = true;
    }

    pub fn disable_monitoring(&mut self) {
        self.monitoring_enabled = false;
    }

    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
        while self.clipboard_data.len() > max_entries {
            self.clipboard_data.remove(0);
        }
    }

    pub fn get_text(&self) -> Option<String> {
        self.clipboard_data.last().and_then(|entry| {
            if entry.format == ClipboardFormat::Text {
                String::from_utf8(entry.data.clone()).ok()
            } else {
                None
            }
        })
    }

    pub fn analyze_sensitivity(&self, data: &[u8]) -> u8 {
        self.analyze_data_sensitivity(data)
    }

    pub fn get_html(&self) -> Option<String> {
        self.clipboard_data.last().and_then(|entry| {
            if entry.format == ClipboardFormat::Html {
                String::from_utf8(entry.data.clone()).ok()
            } else {
                None
            }
        })
    }

    pub fn get_rtf(&self) -> Option<String> {
        self.clipboard_data.last().and_then(|entry| {
            if entry.format == ClipboardFormat::Rtf || entry.format == ClipboardFormat::RichText {
                String::from_utf8(entry.data.clone()).ok()
            } else {
                None
            }
        })
    }

    pub fn get_image(&self) -> Option<ImageData> {
        self.clipboard_data.last().and_then(|entry| {
            if entry.format == ClipboardFormat::Image {
                Some(ImageData { data: entry.data.clone() })
            } else {
                None
            }
        })
    }

    pub fn get_files(&self) -> Vec<String> {
        self.clipboard_data
            .last()
            .and_then(|entry| {
                if entry.format == ClipboardFormat::Files || entry.format == ClipboardFormat::File {
                    String::from_utf8(entry.data.clone())
                        .ok()
                        .map(|s| s.lines().map(|line| String::from(line)).collect())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }
}

impl ClipboardSecurity {
    pub fn new() -> Self {
        ClipboardSecurity {
            blocked_processes: Vec::new(),
            allowed_formats: vec![
                ClipboardFormat::Text,
                ClipboardFormat::Html,
                ClipboardFormat::Image,
                ClipboardFormat::Rtf,
                ClipboardFormat::Csv,
            ],
            max_data_size: 16 * 1024 * 1024,
            cross_process_enabled: true,
            leak_detection_enabled: true,
        }
    }

    pub fn block_process(&mut self, process_id: u32) {
        if !self.blocked_processes.contains(&process_id) {
            self.blocked_processes.push(process_id);
        }
    }

    pub fn unblock_process(&mut self, process_id: u32) {
        self.blocked_processes.retain(|&id| id != process_id);
    }

    pub fn is_process_blocked(&self, process_id: u32) -> bool {
        self.blocked_processes.contains(&process_id)
    }

    pub fn is_format_allowed(&self, format: ClipboardFormat) -> bool {
        self.allowed_formats.contains(&format)
    }

    pub fn add_allowed_format(&mut self, format: ClipboardFormat) {
        if !self.allowed_formats.contains(&format) {
            self.allowed_formats.push(format);
        }
    }

    pub fn remove_allowed_format(&mut self, format: ClipboardFormat) {
        self.allowed_formats.retain(|&f| f != format);
    }

    pub fn set_max_data_size(&mut self, size: usize) {
        self.max_data_size = size;
    }

    pub fn enable_cross_process_access(&mut self) {
        self.cross_process_enabled = true;
    }

    pub fn disable_cross_process_access(&mut self) {
        self.cross_process_enabled = false;
    }
}

static mut CLIPBOARD_MANAGER: Option<ClipboardManager> = None;
static mut CLIPBOARD_SECURITY: Option<ClipboardSecurity> = None;

pub fn init_clipboard() {
    unsafe {
        CLIPBOARD_MANAGER = Some(ClipboardManager::new());
        CLIPBOARD_SECURITY = Some(ClipboardSecurity::new());
    }
}

pub fn clipboard_copy(
    data: &[u8],
    format: ClipboardFormat,
    process_id: u32,
) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref mut manager) = CLIPBOARD_MANAGER {
            if let Some(ref security) = CLIPBOARD_SECURITY {
                if security.is_process_blocked(process_id) {
                    return Err("Process blocked from clipboard access");
                }
                if !security.is_format_allowed(format) {
                    return Err("Clipboard format not allowed");
                }
                if data.len() > security.max_data_size {
                    return Err("Data size exceeds limit");
                }
            }
            manager.copy_data(data, format, process_id)
        } else {
            Err("Clipboard manager not initialized")
        }
    }
}

pub fn clipboard_paste(
    process_id: u32,
    format_filter: Option<ClipboardFormat>,
) -> Result<Vec<u8>, &'static str> {
    unsafe {
        if let Some(ref mut manager) = CLIPBOARD_MANAGER {
            if let Some(ref security) = CLIPBOARD_SECURITY {
                if security.is_process_blocked(process_id) {
                    return Err("Process blocked from clipboard access");
                }
                if !security.cross_process_enabled {
                    return Err("Cross-process clipboard access disabled");
                }
            }
            manager.paste_data(process_id, format_filter)
        } else {
            Err("Clipboard manager not initialized")
        }
    }
}

pub fn clipboard_clear(process_id: u32) -> Result<(), &'static str> {
    unsafe {
        if let Some(ref mut manager) = CLIPBOARD_MANAGER {
            manager.clear_clipboard(process_id)
        } else {
            Err("Clipboard manager not initialized")
        }
    }
}

pub fn get_clipboard_formats() -> Vec<ClipboardFormat> {
    unsafe {
        if let Some(ref manager) = CLIPBOARD_MANAGER {
            manager.get_available_formats()
        } else {
            Vec::new()
        }
    }
}

pub fn get_clipboard_stats() -> Option<ClipboardStatistics> {
    unsafe { CLIPBOARD_MANAGER.as_ref().map(|m| m.get_clipboard_statistics()) }
}

pub fn get_clipboard_data(format: ClipboardFormat) -> Result<Vec<u8>, &'static str> {
    unsafe {
        if let Some(ref manager) = CLIPBOARD_MANAGER {
            match format {
                ClipboardFormat::Text => {
                    manager.get_text().map(|text| text.into_bytes()).ok_or("No text data")
                }
                ClipboardFormat::Html => {
                    manager.get_html().map(|html| html.into_bytes()).ok_or("No HTML data")
                }
                ClipboardFormat::RichText => {
                    manager.get_rtf().map(|rtf| rtf.into_bytes()).ok_or("No RTF data")
                }
                ClipboardFormat::Image => {
                    manager.get_image().map(|img| img.data).ok_or("No image data")
                }
                ClipboardFormat::Files => {
                    let files = manager.get_files();
                    Ok(format!("{:?}", files).into_bytes())
                }
                ClipboardFormat::Audio => Err("Audio format not yet implemented"),
                ClipboardFormat::Video => Err("Video format not yet implemented"),
                ClipboardFormat::File => Err("File format not yet implemented"),
                ClipboardFormat::Binary => Err("Binary format not yet implemented"),
                ClipboardFormat::Rtf => {
                    manager.get_rtf().map(|rtf| rtf.into_bytes()).ok_or("No RTF data")
                }
                ClipboardFormat::Csv => Err("CSV format not yet implemented"),
                ClipboardFormat::Json => Err("JSON format not yet implemented"),
            }
        } else {
            Err("Clipboard manager not initialized")
        }
    }
}

/// Check if clipboard contains sensitive data
pub fn contains_sensitive_data() -> bool {
    unsafe {
        if let Some(ref manager) = CLIPBOARD_MANAGER {
            let content = manager.get_text();
            match content {
                Some(text) => manager.analyze_sensitivity(&text.as_bytes()) > 7,
                None => false,
            }
        } else {
            false
        }
    }
}
