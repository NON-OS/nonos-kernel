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

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

#[derive(Clone)]
pub struct PageLink {
    pub line: usize,
    pub start_x: u32,
    pub end_x: u32,
    pub url: String,
}

pub static PAGE_LINKS: Mutex<Vec<PageLink>> = Mutex::new(Vec::new());
pub static CURRENT_BASE_URL: Mutex<Option<String>> = Mutex::new(None);

pub fn set_base_url(url: &str) {
    *CURRENT_BASE_URL.lock() = Some(String::from(url));
}
pub fn get_base_url() -> Option<String> {
    CURRENT_BASE_URL.lock().clone()
}
pub fn clear_page_links() {
    PAGE_LINKS.lock().clear();
}

pub fn add_page_link(line: usize, start_x: u32, end_x: u32, url: &str) {
    PAGE_LINKS.lock().push(PageLink { line, start_x, end_x, url: String::from(url) });
}

pub fn find_link_at(line: usize, x: u32) -> Option<String> {
    let links = PAGE_LINKS.lock();
    for link in links.iter() {
        if link.line == line && x >= link.start_x && x < link.end_x {
            return Some(link.url.clone());
        }
    }
    None
}

pub fn resolve_relative_url(relative: &str, base: &str) -> String {
    if relative.starts_with("http://") || relative.starts_with("https://") {
        return String::from(relative);
    }
    if relative.starts_with("//") {
        return if base.starts_with("https://") {
            alloc::format!("https:{}", relative)
        } else {
            alloc::format!("http:{}", relative)
        };
    }
    if let Some(scheme_end) = base.find("://") {
        let after_scheme = &base[scheme_end + 3..];
        let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let host = &after_scheme[..host_end];
        let scheme = &base[..scheme_end];
        if relative.starts_with('/') {
            return alloc::format!("{}://{}{}", scheme, host, relative);
        }
        let path = &after_scheme[host_end..];
        let dir = path.rfind('/').map(|i| &path[..i + 1]).unwrap_or("/");
        return alloc::format!("{}://{}{}{}", scheme, host, dir, relative);
    }
    String::from(relative)
}
