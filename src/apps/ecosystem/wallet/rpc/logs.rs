// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::types::RpcResult;
use super::utils::{extract_json_hex_u64, extract_json_string, hex_to_bytes};
use alloc::{format, string::String, vec::Vec};

#[derive(Debug, Clone)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: String,
    pub log_index: u64,
}

impl Log {
    pub(super) fn parse_array(json: &str) -> RpcResult<Vec<Self>> {
        let mut logs = Vec::new();
        let trimmed = json.trim();
        if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
            return Ok(logs);
        }
        let inner = trimmed[1..trimmed.len() - 1].trim();
        if inner.is_empty() {
            return Ok(logs);
        }
        let (mut depth, mut start) = (0, 0);
        for (i, &b) in inner.as_bytes().iter().enumerate() {
            match b {
                b'{' => {
                    if depth == 0 {
                        start = i;
                    }
                    depth += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        if let Ok(log) = Self::parse_single(&inner[start..=i]) {
                            logs.push(log);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(logs)
    }

    fn parse_single(json: &str) -> RpcResult<Self> {
        let mut topics = Vec::new();
        if let Some(topics_start) = json.find("\"topics\"") {
            let rest = &json[topics_start..];
            if let (Some(arr_start), Some(arr_end)) = (rest.find('['), rest.find(']')) {
                let (mut in_string, mut topic_start) = (false, 0);
                for (i, c) in rest[arr_start + 1..arr_end].char_indices() {
                    match c {
                        '"' if !in_string => {
                            in_string = true;
                            topic_start = i + 1;
                        }
                        '"' if in_string => {
                            in_string = false;
                            topics
                                .push(String::from(&rest[arr_start + 1..arr_end][topic_start..i]));
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(Self {
            address: extract_json_string(json, "address").unwrap_or_default(),
            topics,
            data: hex_to_bytes(&extract_json_string(json, "data").unwrap_or_default())
                .unwrap_or_default(),
            block_number: extract_json_hex_u64(json, "blockNumber").unwrap_or(0),
            transaction_hash: extract_json_string(json, "transactionHash").unwrap_or_default(),
            log_index: extract_json_hex_u64(json, "logIndex").unwrap_or(0),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub address: Option<String>,
    pub topics: Vec<Option<String>>,
}

impl LogFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();
        if let Some(from) = self.from_block {
            parts.push(format!(r#""fromBlock":"0x{:x}""#, from));
        }
        if let Some(to) = self.to_block {
            parts.push(format!(r#""toBlock":"0x{:x}""#, to));
        }
        if let Some(ref addr) = self.address {
            parts.push(format!(r#""address":"{}""#, addr));
        }
        if !self.topics.is_empty() {
            let topics_json: Vec<String> = self
                .topics
                .iter()
                .map(|t| t.as_ref().map_or(String::from("null"), |s| format!(r#""{}""#, s)))
                .collect();
            parts.push(format!(r#""topics":[{}]"#, topics_json.join(",")));
        }
        format!("{{{}}}", parts.join(","))
    }
}
