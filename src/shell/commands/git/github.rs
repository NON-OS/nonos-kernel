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
use crate::network::http_client::{HttpClient, HttpRequestOptions};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn parse_github_url(url: &str) -> Option<(String, String)> {
    let url = url.trim_end_matches(".git");
    if url.starts_with("https://github.com/") {
        let rest = &url[19..];
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 2 {
            return Some((String::from(parts[0]), String::from(parts[1])));
        }
    }
    if url.starts_with("git@github.com:") {
        let rest = &url[15..];
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() >= 2 {
            return Some((String::from(parts[0]), String::from(parts[1])));
        }
    }
    None
}

pub(super) fn fetch_repo_tree_with_timeout(
    owner: &str,
    repo: &str,
    branch: &str,
    timeout_ms: u64,
) -> Result<Vec<(String, bool)>, &'static str> {
    let url =
        format!("https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1", owner, repo, branch);
    let opts = HttpRequestOptions { timeout_ms, ..Default::default() };
    let client = HttpClient::with_options(opts);
    let resp = client.get(&url)?;
    if resp.status_code != 200 {
        return Err("GitHub API error");
    }
    parse_tree_response(&resp.body)
}

pub(super) fn fetch_file_with_timeout(
    owner: &str,
    repo: &str,
    branch: &str,
    path: &str,
    timeout_ms: u64,
) -> Result<Vec<u8>, &'static str> {
    let url = format!("https://raw.githubusercontent.com/{}/{}/{}/{}", owner, repo, branch, path);
    let opts = HttpRequestOptions { timeout_ms, ..Default::default() };
    let client = HttpClient::with_options(opts);
    let resp = client.get(&url)?;
    if resp.status_code != 200 {
        return Err("file not found");
    }
    Ok(resp.body)
}

fn parse_tree_response(body: &[u8]) -> Result<Vec<(String, bool)>, &'static str> {
    let s = core::str::from_utf8(body).map_err(|_| "invalid json")?;
    let mut result = Vec::new();
    for line in s.split("\"path\":\"") {
        if let Some(end) = line.find('"') {
            let path = &line[..end];
            let is_dir = line.contains("\"type\":\"tree\"");
            if !path.is_empty() {
                result.push((String::from(path), is_dir));
            }
        }
    }
    Ok(result)
}
