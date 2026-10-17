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

//! The answer, and the four checks it is made of.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{centre_top, left, truncate};

use crate::about::data::proofs::session::{admitted_mark, boot_mark, headline, proven_mark};
use crate::about::data::proofs::{words, Snapshot};

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD, TITLE_PX};
use super::super::mono::valid;
use super::proofs_verdict::{of_headline, of_mark, of_route};
use super::verify_mark::mark;
use super::verify_row::{row, tint, MARK_W};

const HEAD_H: u32 = 44;
const CHECKS: u32 = 4;

pub const HEIGHT: u32 = card::OVERHEAD + HEAD_H + ROW_H * CHECKS + ROW_H + 4;

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, s: &Snapshot) {
    let r = roles();
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, HEIGHT, b"This session");
    let boot = boot_mark(&s.boot);
    let admitted = admitted_mark(s.census.as_ref());
    let proven = proven_mark(s.census.as_ref());
    let h = headline(boot, admitted, proven, s.route);

    let hv = of_headline(h);
    let head_y = top + ((HEAD_H - ROW_H) / 2) as i32;
    mark(fb, CARD_PAD, head_y, hv);
    let text = truncate(valid(words::headline(h)), inner.saturating_sub(MARK_W), TITLE_PX);
    left(fb, CARD_PAD + MARK_W, head_y + centre_top(0, ROW_H, TITLE_PX), &text, tint(hv), TITLE_PX);

    let rows = top + HEAD_H as i32;
    let mut a = [0u8; 48];
    let mut b = [0u8; 48];
    let (admitted_ev, proven_ev): (&[u8], &[u8]) = match &s.census {
        Some(c) => (
            words::of(u64::from(c.admitted), u64::from(c.admitted + c.unadmitted), &mut a),
            words::of(u64::from(c.vendor + c.enrolled), u64::from(c.admitted), &mut b),
        ),
        None => (b"not readable", b"not readable"),
    };
    let checks: [(_, &[u8], &[u8]); CHECKS as usize] = [
        (of_mark(boot), b"the boot chain was verified before the kernel ran", b"signature, attestation, proof"),
        (of_mark(admitted), b"every process holding a capability was admitted by the spawn gate", admitted_ev),
        (of_mark(proven), b"every admitted capsule carries a proof, not only a signature", proven_ev),
        (of_route(s.route), b"the network route is anonymous, up and fresh", words::route_evidence(s.route)),
    ];
    for (i, (v, claim, ev)) in checks.iter().enumerate() {
        row(fb, CARD_PAD, rows + (i as u32 * ROW_H) as i32, inner, *v, claim, ev);
    }

    let note_y = rows + (ROW_H * CHECKS) as i32;
    let mut note = [0u8; 96];
    let n = census_note(s, &mut note);
    left(fb, CARD_PAD, note_y + centre_top(0, ROW_H, BODY_PX), valid(&note[..n]), r.muted, BODY_PX);
}

/* Counted, not tested: the processes outside the registry by design. */
fn census_note(s: &Snapshot, out: &mut [u8; 96]) -> usize {
    let Some(c) = &s.census else {
        return put(out, 0, b"the kernel did not show its process table to this window");
    };
    let mut n = put(out, 0, b"Outside the registry by design: init, and ");
    let mut d = [0u8; 48];
    n = put(out, n, words::of(u64::from(c.sandboxed), u64::from(c.running), &mut d));
    put(out, n, b" capability-free guests")
}

fn put(out: &mut [u8; 96], at: usize, b: &[u8]) -> usize {
    let mut n = at;
    for &c in b {
        if n == out.len() {
            break;
        }
        out[n] = c;
        n += 1;
    }
    n
}
