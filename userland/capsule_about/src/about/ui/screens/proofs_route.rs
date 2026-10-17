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

//! The route: what the system is set to, and each transport's own account,
//! with its age on the board's clock. A transport's row gets the verdict its
//! report would earn if the system were set to it, so both are judged by the
//! same rule while only the chosen one decides the headline.

use nonos_app_skeleton::PaintBuffer;
use nonos_route_proof::{route_verdict, Latest, Network, ROUTE_ANYONE, ROUTE_NYM};
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text;

use crate::about::data::proofs::{words, Snapshot};

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD};
use super::super::mono;
use super::proofs_verdict::of_route;
use super::verify_row::{row, MARK_W};

const PER_TRANSPORT: u32 = 3;

pub const HEIGHT: u32 = card::OVERHEAD + ROW_H + ROW_H * PER_TRANSPORT * 2 + 4;

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, s: &Snapshot) {
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, HEIGHT, b"Route");
    row(fb, CARD_PAD, top, inner, of_route(s.route), set_to(s.chosen), words::route_evidence(s.route));
    let (nym, anyone) = match s.board {
        Some((n, a)) => (n, a),
        None => (None, None),
    };
    let first = top + ROW_H as i32;
    transport(fb, first, inner, Network::Nym, nym, s.board.is_some());
    let second = first + (ROW_H * PER_TRANSPORT) as i32;
    transport(fb, second, inner, Network::Anyone, anyone, s.board.is_some());
}

fn set_to(chosen: Option<u8>) -> &'static [u8] {
    match chosen {
        Some(nonos_route_proof::ROUTE_NYM) => b"this system's traffic is set to the Nym mixnet",
        Some(nonos_route_proof::ROUTE_ANYONE) => b"this system's traffic is set to the Anyone network",
        Some(nonos_route_proof::ROUTE_DIRECT) => b"this system's traffic is set to go direct",
        _ => b"the route this system is set to could not be read",
    }
}

fn transport(fb: &mut PaintBuffer, y: i32, w: u32, n: Network, latest: Latest, board: bool) {
    let muted = roles().muted;
    let as_chosen = match n {
        Network::Nym => ROUTE_NYM,
        Network::Anyone => ROUTE_ANYONE,
    };
    let v = route_verdict(Some(as_chosen), latest);
    let mut claim = [0u8; 64];
    let c = join(&mut claim, words::network(n), b": ", latest.map_or(silent(board), |(r, _)| words::stage(r.stage)));
    let mut age = [0u8; 48];
    let ev: &[u8] = match latest {
        Some((_, ms)) => words::duration(ms, &mut age),
        None => b"",
    };
    row(fb, 0 + CARD_PAD, y, w, of_route(v), &claim[..c], ev);
    let Some((r, ms)) = latest else {
        return;
    };
    let x = CARD_PAD + MARK_W;
    let mut d = [0u8; 48];
    let mut left = [0u8; 48];
    let mut line1 = [0u8; 96];
    let valid = words::duration(r.valid_for_ms.saturating_sub(ms), &mut left);
    let n1 = join3(&mut line1, words::directory(&r, &mut d), b", valid for ", valid);
    let first = y + ROW_H as i32 + text::centre_top(0, ROW_H, BODY_PX);
    text::left(fb, x, first, mono::valid(&line1[..n1]), muted, BODY_PX);
    let mut h = [0u8; 48];
    let mut line2 = [0u8; 96];
    let hops = words::hops(&r, &mut h);
    let n2 = match n {
        Network::Nym if r.cover_traffic => join(&mut line2, hops, b", ", b"cover traffic on"),
        Network::Nym => join(&mut line2, hops, b", ", b"cover traffic off"),
        Network::Anyone => join(&mut line2, hops, b"", b""),
    };
    text::left(fb, x, first + ROW_H as i32, mono::valid(&line2[..n2]), muted, BODY_PX);
}

fn silent(board: bool) -> &'static [u8] {
    if board {
        b"has not reported"
    } else {
        b"route board not reachable"
    }
}

fn join<const N: usize>(out: &mut [u8; N], a: &[u8], b: &[u8], c: &[u8]) -> usize {
    join3(out, a, b, c)
}

fn join3<const N: usize>(out: &mut [u8; N], a: &[u8], b: &[u8], c: &[u8]) -> usize {
    let mut n = 0;
    for part in [a, b, c] {
        for &x in part {
            if n == N {
                return n;
            }
            out[n] = x;
            n += 1;
        }
    }
    n
}
