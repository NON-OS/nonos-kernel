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

//! Where the selected listing stands with this machine.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::{roles, Opaque};
use nonos_toolkit::widgets::text;

use nonos_market_proto::installed_line;

use crate::store::next_step::refused_uninstall;
use crate::store::progress::Progress;
use crate::store::progress_text::waiting_behind;
use crate::store::route_offer::progress_line;
use crate::store::state::State;
use crate::store::theme::Tone;
use crate::store::verdict::Verdict;

use super::bytes::as_str;
use super::gates;
use super::metrics::{BODY_PX, SMALL_PX};
use super::wrap::wrap;

/// At most this many lines of the sentence: a reason a person must act on
/// is read whole, not cut at the pane's edge.
const SENTENCE_LINES: usize = 2;

/// Paints and returns the y to carry on from. `room` is the pane's width
/// for text.
pub fn paint(fb: &mut PaintBuffer, state: &State, left: u32, room: u32, mut top: i32) -> i32 {
    let Some(listing) = state.current() else { return top };
    match listing.known.readiness {
        Some(r) => {
            let v = Verdict::of(&r);
            let hue = match v {
                Verdict::Ready => Tone::Ok,
                Verdict::Installed => Tone::Accent,
                Verdict::Blocked => Tone::Danger,
            };
            /*
             * Once the person has asked, what happened is the headline; the
             * verdict from before they asked would contradict it. Installed
             * says where it is held, which differs by kind and by boot
             * (`installed_line`): never "kept" for what goes at restart.
             */
            let (line, tone) = match listing.progress {
                Progress::Installed => (installed_line(&listing.id).as_bytes(), Tone::Ok),
                p if refused_uninstall(p, listing.removing) => {
                    let said = b"The system would not start the uninstall; press u to ask again";
                    (&said[..], Tone::Danger)
                }
                p => p.sentence().unwrap_or((v.sentence(), hue)),
            };
            /*
             * While a tier's model comes, what the fetcher says of it is the
             * headline: how far, or which exit it is waiting on.
             */
            let fetching = state.fetch_of(listing).map(|s| progress_line(&s));
            /* Queued behind another install: which, and how far it has got. */
            let behind = (listing.progress == Progress::Queued)
                .then(|| state.ahead_of(listing))
                .flatten()
                .map(|ahead| {
                    let how = state.fetch_of(ahead).map(|s| progress_line(&s));
                    waiting_behind(&ahead.name, how.as_deref())
                });
            let (line, tone) = match (&fetching, &behind) {
                (Some(said), _) => (said.as_bytes(), Tone::Accent),
                (None, Some(said)) => (&said[..], Tone::Muted),
                (None, None) => (line, tone),
            };
            for part in wrap(line, room, BODY_PX).iter().take(SENTENCE_LINES) {
                text::left(fb, left, top, as_str(part), ink(tone), BODY_PX);
                top += 22;
            }
            top += 8;
            top = super::tier_path::paint(fb, state, listing, left, room, top);
            /*
             * Where the gates end, not a guess at their height: a guess once
             * put the measurement on top of the last gate.
             */
            top = gates::paint(fb, left, room, top, &r) + 14;
        }
        /*
         * Asked and not answered, or the market went quiet before this one
         * was asked: say so, rather than "checking" for ever.
         */
        None if listing.known.judged || state.port == 0 => {
            let said = "the market did not say; press r to ask again";
            text::left(fb, left, top, said, roles().danger, SMALL_PX);
            top += 26;
        }
        None => {
            text::left(fb, left, top, "checking", roles().muted, SMALL_PX);
            top += 26;
        }
    }
    top
}

/// The role a tone of the store's words is painted in.
fn ink(tone: Tone) -> Opaque {
    let r = roles();
    match tone {
        Tone::Muted => r.muted,
        Tone::Accent => r.accent,
        Tone::Ok => r.ok,
        Tone::Danger => r.danger,
    }
}
