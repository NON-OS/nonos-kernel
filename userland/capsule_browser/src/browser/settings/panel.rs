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
use alloc::format;
use alloc::string::String;

use nonos_app_skeleton::PaintBuffer;

use super::geometry::{panel_x, PANEL_H, PANEL_TOP, PANEL_W, PROXY_Y, ROWS, ROW_H, ROW_STEP};
use super::geometry::{FIRST_ROW_Y, SEARCH_Y};
use crate::browser::net::mixnet::{self, Network};
use crate::browser::paint::tokens;
use crate::browser::state::State;

/// What the panel and the address bar say the next request leaves through.
/// A manual proxy only carries traffic on the direct network, so it is named
/// there and nowhere else.
pub fn network_line(state: &State) -> String {
    match (mixnet::chosen(), state.proxy.as_ref()) {
        (Network::Direct, Some(p)) => {
            format!("Network: direct, SOCKS5 proxy {}:{}", p.host, p.port)
        }
        (net, _) => format!("Network: {}", net.label()),
    }
}

/// Draw the panel over the page when it is open: the network requests leave
/// through, a row per network with the chosen one marked, the proxy row and
/// the search engine address bar text goes to.
pub fn paint(state: &State, fb: &mut PaintBuffer) {
    if !state.settings_open {
        return;
    }
    let x = panel_x(fb.width as i32);
    let (px, top, w, h) = (x as u32, PANEL_TOP as u32, PANEL_W as u32, PANEL_H as u32);
    fb.fill_rect(px, top, w, h, tokens::EDGE);
    fb.fill_rect(px + 1, top + 1, w - 2, h - 2, tokens::SURFACE);
    fb.fill_rect(px, top, w, 2, tokens::ACCENT);
    fb.text_ttf(x + 14, PANEL_TOP + 12, "Settings", tokens::INK, 16.0);
    fb.text_ttf(x + 14, PANEL_TOP + 42, &network_line(state), tokens::MUTED, 14.0);
    let chosen = mixnet::chosen();
    for (i, net) in ROWS.iter().enumerate() {
        button(fb, x, FIRST_ROW_Y + i as i32 * ROW_STEP, net.label(), *net == chosen);
    }
    let proxy = if state.proxy.is_some() { "Turn proxy off" } else { "Set proxy (type host:port)" };
    button(fb, x, PROXY_Y, proxy, false);
    let engine = state.ui.search.split('/').nth(2).unwrap_or("");
    fb.text_ttf(x + 14, SEARCH_Y, &format!("Search: {}", engine), tokens::MUTED, 14.0);
}

fn button(fb: &mut PaintBuffer, x: i32, y: i32, label: &str, active: bool) {
    let w = (PANEL_W - 24) as u32;
    fb.fill_rect((x + 12) as u32, y as u32, w, ROW_H as u32, tokens::FIELD);
    if active {
        fb.fill_rect((x + 12) as u32, y as u32, 4, ROW_H as u32, tokens::ACCENT);
    }
    let color = if active { tokens::ACCENT } else { tokens::INK };
    fb.text_ttf(x + 24, y + 8, label, color, 14.0);
}
