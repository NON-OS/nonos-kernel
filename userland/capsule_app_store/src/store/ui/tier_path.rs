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

//! The path a Qwen tier's model takes, in the detail pane: while it comes,
//! how far, how fast and by which network; before Install, the network it
//! would leave by, and for a large download through Nym or Anyone the
//! estimate and the offer of a direct one, which `d` takes. The stick tier
//! says it is imported from a release stick with no network when this
//! stick carries it; whether it does is the kernel's to say at the import.

use alloc::string::String;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::{roles, Opaque};
use nonos_toolkit::widgets::text;

use crate::need::STICK_TIER;
use crate::store::listing::Listing;
use crate::store::model_weights::MODEL_WEIGHTS;
use crate::store::route_offer::{installs, path_line, store_offer};
use crate::store::state::State;
use crate::store::tier_fit::{tier_of, weight};

use super::bytes::as_str;
use super::metrics::SMALL_PX;
use super::wrap::wrap;

const STICK: &str = "The stick tier: Install imports it from a release stick with no \
     network when this stick carries it, and downloads it otherwise.";

/// Paints and returns the y to carry on from.
pub fn paint(fb: &mut PaintBuffer, state: &State, l: &Listing, left: u32, room: u32, top: i32) -> i32 {
    let Some(tier) = tier_of(&l.id) else { return top };
    let r = roles();
    let mut said: [(Option<String>, Opaque); 3] =
        [(None, r.muted), (None, r.muted), (None, r.accent)];
    if state.fetch_of(l).is_some() {
        /* The headline above says how far it has come. */
    } else if l.progress.uninstalled() {
        said[0].0 = (tier == STICK_TIER).then(|| String::from(STICK));
        said[1].0 = Some(path_line(state.route));
        said[2].0 = weight(tier, MODEL_WEIGHTS).and_then(|w| store_offer(installs(state.route), w));
    }
    let mut top = top;
    for (line, tone) in said.iter().filter_map(|(l, t)| l.as_ref().map(|l| (l, *t))) {
        for part in wrap(line.as_bytes(), room, SMALL_PX).iter().take(2) {
            text::left(fb, left, top, as_str(part), tone, SMALL_PX);
            top += 20;
        }
        top += 4;
    }
    top
}
