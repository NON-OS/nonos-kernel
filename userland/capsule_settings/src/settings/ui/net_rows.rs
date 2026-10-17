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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Rect, Row, Scrolled};

use crate::settings::state::wifi_pending::Work;
use crate::settings::state::State;

use super::bytes::as_str;
use super::control_geom::right_edge;
use super::hover_look::{look, pointed};
use super::metrics::BODY_PX;
use super::net_signal::draw_bars;
use super::target::Target;
use super::text;
use super::valbuf::ValBuf;
use crate::wifi::ScanStats;

/// One scanned network at `at`, in content coordinates, through the toolkit
/// row; the signal bars and the words beside them stay in the room the row
/// leaves at its right end. The list is empty until a scan runs, and an empty
/// list says so rather than drawing nothing.
pub fn paint(fb: &mut PaintBuffer, state: &State, index: usize, scroll: u32, at: Rect) {
    let r = roles();
    let screen_y = at.y as i32 - scroll as i32;
    let right = right_edge(at.x, at.w);
    let top = text::centred_top(0, at.h, BODY_PX) + screen_y;
    if state.wifi_network_count == 0 {
        let scanning = state.wifi.pending.work() == Some(Work::Scan);
        let mut why = ValBuf::new();
        let label = if scanning {
            "Scanning..."
        } else {
            empty_scan(&mut why, state.wifi_stats);
            why.as_str()
        };
        let room = text::width(fb, "Scan", BODY_PX);
        let line = Row::new(label).trailing(room).state(pointed(state, |t| t == Target::Scan));
        line.draw(&mut Scrolled::new(fb, scroll), at);
        text::right(fb, right, top, "Scan", r.muted.argb(), BODY_PX);
        return;
    }
    let i = index.min(state.wifi_network_count - 1);
    let selected = i == state.wifi_cursor;
    let look = look(state, |t| t == Target::Network(i), selected);
    let net = state.wifi_networks[i];
    let joined = state.wifi.joined() == Some(net.ssid());
    let note = match (state.wifi.is_saved(net.ssid()), net.secured) {
        (true, _) => "Saved",
        (false, true) => "Secured",
        (false, false) => "Open",
    };
    let room = if joined { CONNECTED_AT + text::width(fb, "Connected", BODY_PX) } else { BARS_W };
    let line = Row::new(as_str(net.ssid())).note(note).trailing(room).state(look);
    line.draw(&mut Scrolled::new(fb, scroll), at);
    draw_bars(fb, right, screen_y + (at.h / 2) as i32, net.signal);
    if joined {
        text::right(fb, right - CONNECTED_AT, top, "Connected", r.ok.argb(), BODY_PX);
    }
}

/// The width the signal bars take at a row's right end.
const BARS_W: u32 = 24;

/// How far left of the row's right edge "Connected" ends, clear of the bars.
const CONNECTED_AT: u32 = 26;

/*
 * An empty list says where reception stopped, from the driver's scan counters:
 * frames the radio received on the channels it swept, and how many parsed as
 * beacons. No frames is a receiver that hears nothing; frames but no beacons is
 * a parse that fails. Before any sweep the plain line stands.
 */
fn empty_scan(b: &mut ValBuf, stats: ScanStats) {
    if stats.steps == 0 {
        b.push_str("No networks found");
        return;
    }
    b.push_str("No networks: ");
    b.push_dec(stats.raw);
    b.push_str(" frames, ");
    b.push_dec(stats.beacons);
    b.push_str(" beacons heard");
}
