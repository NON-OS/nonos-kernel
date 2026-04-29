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

use super::state;
use alloc::string::String;

pub(super) fn go_back() {
    use crate::apps::ecosystem::browser::{state as browser_state, tabs};
    let tab_id = browser_state::get_active_tab_id();
    if tabs::go_back_tab(tab_id) {
        if let Some(tab) = browser_state::get_tab(tab_id) {
            state::set_url(&tab.url);
            crate::apps::ecosystem::browser::navigate(&tab.url);
        }
    }
}

pub(super) fn go_forward() {
    use crate::apps::ecosystem::browser::{state as browser_state, tabs};
    let tab_id = browser_state::get_active_tab_id();
    if tabs::go_forward_tab(tab_id) {
        if let Some(tab) = browser_state::get_tab(tab_id) {
            state::set_url(&tab.url);
            crate::apps::ecosystem::browser::navigate(&tab.url);
        }
    }
}

pub(super) fn reload() {
    navigate_to_url();
}

pub(super) fn navigate_to_url() {
    if let Some(url) = state::get_url_string() {
        let url = if !url.starts_with("http://") && !url.starts_with("https://") {
            alloc::format!("https://{}", url)
        } else {
            url
        };
        crate::apps::ecosystem::browser::navigate(&url);
    }
}

pub(super) fn handle_link_click(line: usize, x: u32) {
    let actual_line = line;
    if let Some(url) = state::find_link_at(actual_line, x) {
        let resolved = if url.starts_with("http://") || url.starts_with("https://") {
            url
        } else if let Some(base) = state::get_base_url() {
            state::resolve_relative_url(&url, &base)
        } else {
            url
        };
        state::set_url(&resolved);
        crate::apps::ecosystem::browser::navigate(&resolved);
        return;
    }
    let url_to_navigate: Option<String> = {
        let content = state::PAGE_CONTENT.lock();
        if actual_line < content.len() {
            let line_text = &content[actual_line];
            if let Some(start) = line_text.find('[') {
                if let Some(end) = line_text.find(']') {
                    if start < end && end > start + 1 {
                        let url = &line_text[start + 1..end];
                        if url.starts_with("http://")
                            || url.starts_with("https://")
                            || url.starts_with("/")
                        {
                            Some(String::from(url))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(url) = url_to_navigate {
        let resolved = if url.starts_with("http://") || url.starts_with("https://") {
            url
        } else if let Some(base) = state::get_base_url() {
            state::resolve_relative_url(&url, &base)
        } else {
            url
        };
        state::set_url(&resolved);
        crate::apps::ecosystem::browser::navigate(&resolved);
    }
}

pub(super) fn create_new_wallet() {
    match crate::apps::ecosystem::wallet::create_wallet() {
        Ok(address) => {
            state::set_wallet_address(&address);
            state::set_wallet_balance("0.00");
        }
        Err(_) => {
            state::set_error("Failed to create wallet");
        }
    }
}

pub(super) fn import_wallet() {
    let seed_phrase = state::get_import_seed_phrase();
    if seed_phrase.is_empty() {
        state::set_error("Enter seed phrase to import wallet");
        return;
    }
    match crate::apps::ecosystem::wallet::import_from_mnemonic(&seed_phrase) {
        Ok(address) => {
            state::set_wallet_address(&address);
            state::clear_import_seed_phrase();
            crate::graphics::window::notify_success(b"Wallet imported successfully");
        }
        Err(e) => {
            state::set_error(&alloc::format!("Import failed: {}", e));
        }
    }
}

pub(super) fn send_transaction() {
    let recipient = match state::get_send_recipient() {
        Some(r) => r,
        None => {
            state::set_error("Enter recipient address");
            return;
        }
    };
    let amount = match state::get_send_amount() {
        Some(a) => a,
        None => {
            state::set_error("Enter amount to send");
            return;
        }
    };
    match crate::apps::ecosystem::wallet::send_tokens(&recipient, amount) {
        Ok(tx_hash) => {
            let msg = alloc::format!("Transaction sent: {}", tx_hash);
            crate::graphics::window::notify_success(msg.as_bytes());
            state::clear_send_fields();
        }
        Err(e) => {
            state::set_error(&alloc::format!("Send failed: {}", e));
        }
    }
}

pub(super) fn show_receive_address() {
    if let Some(addr) = state::get_wallet_address() {
        let msg = alloc::format!("Address: {}", addr);
        crate::graphics::window::notify_info(msg.as_bytes());
    }
}

pub(super) fn page_up() {
    state::scroll_up(10);
    state::mark_content_changed();
}

pub(super) fn page_down() {
    state::scroll_down(10);
    state::mark_content_changed();
}

pub(super) fn scroll_up_line() {
    state::scroll_up(1);
    state::mark_content_changed();
}

pub(super) fn scroll_down_line() {
    state::scroll_down(1);
    state::mark_content_changed();
}
