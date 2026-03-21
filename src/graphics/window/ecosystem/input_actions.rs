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

use alloc::string::String;
use core::sync::atomic::Ordering;
use super::state;

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
    // `line` is already scroll-adjusted by the caller.
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
                        if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("/") {
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
}

pub(super) fn send_transaction() {
}

pub(super) fn show_receive_address() {
    if let Some(addr) = state::get_wallet_address() {
        let msg = alloc::format!("Address: {}", addr);
        crate::graphics::window::notify_info(msg.as_bytes());
    }
}

pub(super) fn open_swap() {
}

pub(super) fn stake_tokens() {
}

pub(super) fn unstake_tokens() {
}

pub(super) fn claim_rewards() {
    match crate::apps::ecosystem::staking::claim_pending_rewards() {
        Ok(amount) => {
            let msg = alloc::format!("Claimed {} NOX", amount);
            crate::graphics::window::notify_success(msg.as_bytes());
        }
        Err(err) => {
            let msg = alloc::format!("Failed to claim rewards: {}", err);
            state::set_error(&msg);
        }
    }
}

pub(super) fn add_liquidity() {
}

pub(super) fn remove_liquidity() {
}

pub(super) fn compound_lp() {
    match crate::apps::ecosystem::lp::auto_compound() {
        Ok(_) => {
            crate::graphics::window::notify_success(b"LP compounded successfully");
        }
        Err(err) => {
            let msg = alloc::format!("Failed to compound LP: {}", err);
            state::set_error(&msg);
        }
    }
}

pub(super) fn connect_node() {
    state::NODE_CONNECTED.store(true, Ordering::Relaxed);
    state::NODE_PEERS.store(12, Ordering::Relaxed);
    state::NODE_BLOCK_HEIGHT.store(19_500_000, Ordering::Relaxed);
    state::NODE_SYNC_PROGRESS.store(100, Ordering::Relaxed);
}

pub(super) fn disconnect_node() {
    state::NODE_CONNECTED.store(false, Ordering::Relaxed);
    state::NODE_PEERS.store(0, Ordering::Relaxed);
    state::NODE_SYNC_PROGRESS.store(0, Ordering::Relaxed);
}

pub(super) fn open_node_settings() {
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
