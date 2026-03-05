// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

use super::constants::*;

pub(crate) static URL_BUFFER: Mutex<[u8; MAX_URL_LEN]> = Mutex::new([0u8; MAX_URL_LEN]);
pub(crate) static URL_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static URL_CURSOR: AtomicUsize = AtomicUsize::new(0);
pub(crate) static URL_FOCUSED: AtomicBool = AtomicBool::new(true);

pub(crate) static LOADING: AtomicBool = AtomicBool::new(false);
pub(crate) static LOAD_ERROR: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchState {
    Idle,
    ResolvingDns,
    Connecting,
    Fetching,
    Parsing,
    Done,
    Error,
}

pub(crate) static FETCH_STATE: spin::Mutex<FetchState> = spin::Mutex::new(FetchState::Idle);
pub(crate) static FETCH_URL: spin::Mutex<[u8; 512]> = spin::Mutex::new([0u8; 512]);
pub(crate) static FETCH_URL_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FETCH_HOST: spin::Mutex<[u8; 256]> = spin::Mutex::new([0u8; 256]);
pub(crate) static FETCH_HOST_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FETCH_PATH: spin::Mutex<[u8; 256]> = spin::Mutex::new([0u8; 256]);
pub(crate) static FETCH_PATH_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FETCH_PORT: AtomicUsize = AtomicUsize::new(80);
pub(crate) static FETCH_HTTPS: AtomicBool = AtomicBool::new(false);
pub(crate) static FETCH_IP: spin::Mutex<[u8; 4]> = spin::Mutex::new([0u8; 4]);
pub(crate) static FETCH_START_MS: AtomicUsize = AtomicUsize::new(0);
pub static FETCH_CONN_ID: AtomicUsize = AtomicUsize::new(0);

pub(crate) static PAGE_LINES: Mutex<Vec<(String, u32)>> = Mutex::new(Vec::new());
pub(crate) static PAGE_TITLE: Mutex<[u8; MAX_TITLE_LEN]> = Mutex::new([0u8; MAX_TITLE_LEN]);
pub(crate) static PAGE_TITLE_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static SCROLL_OFFSET: AtomicUsize = AtomicUsize::new(0);

pub(crate) static STATUS_MSG: Mutex<[u8; MAX_STATUS_LEN]> = Mutex::new([0u8; MAX_STATUS_LEN]);
pub(crate) static STATUS_LEN: AtomicUsize = AtomicUsize::new(0);

pub(crate) static HISTORY: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub(crate) static HISTORY_POS: AtomicUsize = AtomicUsize::new(0);

pub(crate) static PAGE_LINKS: Mutex<Vec<(usize, usize, usize, String)>> = Mutex::new(Vec::new());

pub(crate) fn clear_links() {
    let mut links = PAGE_LINKS.lock();
    links.clear();
}

pub(crate) fn add_link(line: usize, start: usize, end: usize, href: String) {
    let mut links = PAGE_LINKS.lock();
    links.push((line, start, end, href));
}

pub(crate) fn find_link_at(line: usize, char_offset: usize) -> Option<String> {
    let links = PAGE_LINKS.lock();
    for (l, start, end, href) in links.iter() {
        if *l == line && char_offset >= *start && char_offset < *end {
            return Some(href.clone());
        }
    }
    None
}

pub(crate) fn set_status(msg: &[u8]) {
    let mut status = STATUS_MSG.lock();
    let len = msg.len().min(MAX_STATUS_LEN - 1);
    status[..len].copy_from_slice(&msg[..len]);
    STATUS_LEN.store(len, Ordering::Relaxed);
}

pub(crate) fn get_url_string() -> Option<String> {
    let url_buf = URL_BUFFER.lock();
    let url_len = URL_LEN.load(Ordering::Relaxed);
    if url_len > 0 {
        core::str::from_utf8(&url_buf[..url_len])
            .ok()
            .map(String::from)
    } else {
        None
    }
}

pub(crate) fn set_url(url: &str) {
    let mut url_buf = URL_BUFFER.lock();
    let len = url.len().min(MAX_URL_LEN - 1);
    url_buf[..len].copy_from_slice(&url.as_bytes()[..len]);
    URL_LEN.store(len, Ordering::Relaxed);
    URL_CURSOR.store(len, Ordering::Relaxed);
}

pub(crate) fn clear_page() {
    let mut lines = PAGE_LINES.lock();
    lines.clear();
    SCROLL_OFFSET.store(0, Ordering::Relaxed);
    PAGE_TITLE_LEN.store(0, Ordering::Relaxed);
}

pub(crate) fn can_go_back() -> bool {
    HISTORY_POS.load(Ordering::Relaxed) > 1
}

pub(crate) fn can_go_forward() -> bool {
    let history = HISTORY.lock();
    let pos = HISTORY_POS.load(Ordering::Relaxed);
    pos < history.len()
}
