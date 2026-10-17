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

//! One listing, drawn as a card: the toolkit's `Card` is the box, and the
//! tile, the two lines and the controls are drawn inside it.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{text, Button, Card, Kind, Rect, State as Look};

use crate::store::listing::{Listing, Source};
use crate::store::model_card::model_line;
use crate::store::model_weights::MODEL_WEIGHTS;
use crate::status_wire::Status;
use crate::store::progress::Progress;
use crate::store::route_offer::progress_line;
use crate::store::state::State;

use super::bytes::as_str;
use super::geometry::{action_rect, remove_rect};
use super::hover_look::{look, pointed};
use super::metrics::{CARD_H, CARD_PAD, NAME_PX, SMALL_PX, TILE, TILE_GAP};
use super::target::Target;

/// The card at `at` in the visible list. The keyboard cursor's card draws
/// the focus ring, and the card and its buttons draw the pointer's hover and
/// press.
pub fn paint(
    fb: &mut PaintBuffer,
    l: &Listing,
    fetch: Option<Status>,
    (x, y, w): (u32, u32, u32),
    (state, at): (&State, usize),
) {
    let r = roles();
    let card = look(state, |t| t.on_card(at), at == state.cursor);
    Card::new().state(card).draw(fb, Rect { x, y, w, h: CARD_H });

    let tile_y = y + (CARD_H - TILE) / 2;
    fb.blend_rect(x + CARD_PAD, tile_y, TILE, TILE, tint(l.source));
    let initial = [l.name.first().copied().unwrap_or(b'?').to_ascii_uppercase()];
    let initial = as_str(&initial);
    let ix = x + CARD_PAD + (TILE - text::width(initial, NAME_PX)) / 2;
    text::left(fb, ix, text::centre_top(tile_y, TILE, NAME_PX), initial, r.text, NAME_PX);

    let text_x = x + CARD_PAD + TILE + TILE_GAP;
    text::left(fb, text_x, y as i32 + 12, as_str(&l.name), r.text, NAME_PX);
    /*
     * A Qwen tier says what it downloads and the memory it needs, and while
     * its model comes, how far it has come (`route_offer::progress_line`).
     */
    let sub = y as i32 + 34;
    match (fetch, model_line(&l.id, MODEL_WEIGHTS)) {
        (Some(s), _) => text::left(fb, text_x, sub, &progress_line(&s), r.accent, SMALL_PX),
        (None, Some(line)) => text::left(fb, text_x, sub, as_str(&line), r.muted, SMALL_PX),
        (None, None) => text::left(fb, text_x, sub, as_str(l.source.origin()), r.muted, SMALL_PX),
    };

    action(fb, l, action_rect(x, y, w), pointed(state, |t| t == Target::Action(at)));
    if l.progress == Progress::Installed {
        let (x, y, w, h) = remove_rect(x, y, w);
        let look = pointed(state, |t| t == Target::Remove(at));
        Button::new("Remove").kind(Kind::Danger).state(look).draw(fb, Rect { x, y, w, h });
    }
}

/// The install action, filled rather than lettered where it is the offer:
/// a coloured word is not obviously a control. `look` is the pointer's; a
/// disabled action ignores it.
fn action(fb: &mut PaintBuffer, l: &Listing, (x, y, w, h): (u32, u32, u32, u32), look: Look) {
    let (kind, disabled) = match l.progress {
        p if p.uninstalled() && l.ready => (Kind::Primary, false),
        Progress::Installed => (Kind::Primary, false),
        Progress::Queued | Progress::Installing | Progress::Removing => (Kind::Plain, false),
        p if p.needs_installed_system() => (Kind::Secondary, true),
        p if p.retryable() => (Kind::Danger, false),
        Progress::Refused | Progress::Failed(_) | Progress::Idle | Progress::Removed => {
            (Kind::Secondary, false)
        }
    };
    let look = Look { disabled, ..look };
    let button = Button::new(as_str(l.progress.button(l.ready))).kind(kind).state(look);
    button.draw(fb, Rect { x, y, w, h });
}

/// The tile behind a listing's initial, tinted per source so the namespaces
/// are told apart before a word is read. No role is a category colour, so
/// each takes the nearest ground that still differs from the card.
fn tint(source: Source) -> u32 {
    let r = roles();
    match source {
        Source::NonOs => r.accent_wash.argb(),
        Source::Linux | Source::Model => r.raised.argb(),
        Source::Community => r.border.argb(),
    }
}
