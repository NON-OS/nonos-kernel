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


extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use spin::RwLock;

const MAX_HISTORY_ENTRIES: usize = 10000;

static BROWSER_HISTORY: RwLock<VecDeque<HistoryEntry>> = RwLock::new(VecDeque::new());

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub timestamp: u64,
    pub visit_count: u32,
}

impl HistoryEntry {
    pub fn new(url: &str, title: &str) -> Self {
        Self {
            url: String::from(url),
            title: String::from(title),
            timestamp: crate::time::timestamp_secs(),
            visit_count: 1,
        }
    }

    pub fn domain(&self) -> Option<String> {
        let start = if self.url.starts_with("https://") {
            8
        } else if self.url.starts_with("http://") {
            7
        } else {
            return None;
        };

        let rest = &self.url[start..];
        let end = rest.find('/').unwrap_or(rest.len());
        let domain = &rest[..end];

        let domain = if let Some(colon_pos) = domain.find(':') {
            &domain[..colon_pos]
        } else {
            domain
        };

        Some(String::from(domain))
    }

    pub fn formatted_time(&self) -> String {
        let secs = self.timestamp;
        let hours = (secs / 3600) % 24;
        let minutes = (secs / 60) % 60;
        alloc::format!("{:02}:{:02}", hours, minutes)
    }

    pub fn formatted_date(&self) -> String {
        let days = self.timestamp / 86400;
        let year = 1970 + (days / 365);
        let remaining_days = days % 365;
        let month = (remaining_days / 30) + 1;
        let day = (remaining_days % 30) + 1;
        alloc::format!("{:04}-{:02}-{:02}", year, month, day)
    }
}

pub fn add_history(url: &str, title: &str) {
    if url.is_empty() || url == "about:blank" {
        return;
    }

    let mut history = BROWSER_HISTORY.write();

    if let Some(existing) = history.iter_mut().find(|e| e.url == url) {
        existing.visit_count += 1;
        existing.timestamp = crate::time::timestamp_secs();
        if !title.is_empty() {
            existing.title = String::from(title);
        }
        return;
    }

    if history.len() >= MAX_HISTORY_ENTRIES {
        history.pop_back();
    }

    let entry = HistoryEntry::new(url, title);
    history.push_front(entry);
}

pub fn get_history() -> Vec<HistoryEntry> {
    let history = BROWSER_HISTORY.read();
    history.iter().cloned().collect()
}

pub fn get_history_range(start: usize, count: usize) -> Vec<HistoryEntry> {
    let history = BROWSER_HISTORY.read();
    history.iter().skip(start).take(count).cloned().collect()
}

pub fn search_history(query: &str) -> Vec<HistoryEntry> {
    let query_lower = query.to_ascii_lowercase();
    let history = BROWSER_HISTORY.read();

    history
        .iter()
        .filter(|entry| {
            entry.url.to_ascii_lowercase().contains(&query_lower)
                || entry.title.to_ascii_lowercase().contains(&query_lower)
        })
        .cloned()
        .collect()
}

pub fn get_history_for_domain(domain: &str) -> Vec<HistoryEntry> {
    let history = BROWSER_HISTORY.read();

    history
        .iter()
        .filter(|entry| entry.domain().as_deref() == Some(domain))
        .cloned()
        .collect()
}

pub fn get_recent_history(count: usize) -> Vec<HistoryEntry> {
    let history = BROWSER_HISTORY.read();
    history.iter().take(count).cloned().collect()
}

pub fn get_most_visited(count: usize) -> Vec<HistoryEntry> {
    let history = BROWSER_HISTORY.read();
    let mut entries: Vec<HistoryEntry> = history.iter().cloned().collect();
    entries.sort_by(|a, b| b.visit_count.cmp(&a.visit_count));
    entries.truncate(count);
    entries
}

pub fn remove_history_entry(url: &str) -> bool {
    let mut history = BROWSER_HISTORY.write();
    if let Some(pos) = history.iter().position(|e| e.url == url) {
        history.remove(pos);
        true
    } else {
        false
    }
}

pub fn remove_history_range(start_time: u64, end_time: u64) {
    let mut history = BROWSER_HISTORY.write();
    history.retain(|entry| entry.timestamp < start_time || entry.timestamp > end_time);
}

pub fn clear_history() {
    let mut history = BROWSER_HISTORY.write();
    history.clear();
}

pub fn history_count() -> usize {
    BROWSER_HISTORY.read().len()
}

pub fn get_suggestions(partial_url: &str, max_results: usize) -> Vec<String> {
    let partial_lower = partial_url.to_ascii_lowercase();
    let history = BROWSER_HISTORY.read();

    let mut suggestions: Vec<(String, u32)> = history
        .iter()
        .filter(|entry| entry.url.to_ascii_lowercase().contains(&partial_lower))
        .map(|entry| (entry.url.clone(), entry.visit_count))
        .collect();

    suggestions.sort_by(|a, b| b.1.cmp(&a.1));

    suggestions
        .into_iter()
        .take(max_results)
        .map(|(url, _)| url)
        .collect()
}

pub fn export_history() -> Vec<u8> {
    let history = BROWSER_HISTORY.read();
    let mut output = String::new();

    output.push_str("url,title,timestamp,visit_count\n");

    for entry in history.iter() {
        let escaped_title = entry.title.replace(',', "\\,").replace('\n', "\\n");
        output.push_str(&alloc::format!(
            "{},{},{},{}\n",
            entry.url, escaped_title, entry.timestamp, entry.visit_count
        ));
    }

    output.into_bytes()
}

pub fn import_history(data: &[u8]) -> usize {
    let text = match core::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return 0,
    };

    let mut count = 0;
    let mut history = BROWSER_HISTORY.write();

    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.splitn(4, ',').collect();
        if parts.len() >= 4 {
            let url = parts[0];
            let title = parts[1].replace("\\,", ",").replace("\\n", "\n");
            let timestamp: u64 = parts[2].parse().unwrap_or(0);
            let visit_count: u32 = parts[3].parse().unwrap_or(1);

            let entry = HistoryEntry {
                url: String::from(url),
                title,
                timestamp,
                visit_count,
            };

            history.push_back(entry);
            count += 1;
        }
    }

    while history.len() > MAX_HISTORY_ENTRIES {
        history.pop_back();
    }

    count
}
