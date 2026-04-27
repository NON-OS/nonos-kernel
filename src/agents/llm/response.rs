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

use crate::agents::core::AgentConfig;
use alloc::vec::Vec;

pub(super) fn format_tool_response(result: &[u8], _config: &AgentConfig) -> Vec<u8> {
    let s = core::str::from_utf8(result).unwrap_or("");
    if s.is_empty() {
        return b"Operation completed (no output).".to_vec();
    }
    if s == "ok" {
        return b"Done!".to_vec();
    }
    if s.contains("not found") || s.contains("error") {
        return alloc::format!("Issue: {}", s).into_bytes();
    }
    if s.len() > 500 {
        return alloc::format!("Result:\n\n{}...\n\n({} bytes total)", &s[..500], s.len())
            .into_bytes();
    }
    alloc::format!("Result:\n\n{}", s).into_bytes()
}

pub(super) fn help_response() -> Vec<u8> {
    b"I can help you with:\n\
    - List files: \"list files in /ram\"\n\
    - Read files: \"read file /ram/test.txt\"\n\
    - Write files: \"write file /ram/note.txt content hello\"\n\
    - Run commands: \"run ls\" or \"execute uname -a\"\n\
    - System info: \"show system info\"\n\
    - Wallet: \"check balance\"\n\
    Just ask naturally!"
        .to_vec()
}

pub(super) fn context_response(query: &str) -> Vec<u8> {
    let words: Vec<&str> = query.split_whitespace().collect();
    if words.len() < 2 {
        return b"Could you tell me more about what you'd like to do?".to_vec();
    }
    if query.contains("create") || query.contains("make") || query.contains("new") {
        return b"I can create files. Try: \"write file /ram/name.txt content text\"".to_vec();
    }
    if query.contains("delete") || query.contains("remove") {
        return b"To remove a file: \"run rm /ram/filename\"".to_vec();
    }
    if query.contains("find") || query.contains("search") {
        return b"To search: \"run find /ram -name pattern\"".to_vec();
    }
    if query.contains("open") {
        return b"<tool>open_app terminal</tool>".to_vec();
    }
    alloc::format!("I understand '{}'. Type 'help' for options.", words[0]).into_bytes()
}
