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

//! Toast: `hit` is true on exactly the box the action draws its hover, press
//! and focus in, and false on the rest of the toast and off it; with no
//! action nothing is hit. The tone moves nothing, so one tone is enough.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::rect::contains;
use nonos_toolkit::widgets::{Rect, Toast};

use super::boxes::boxes;
use super::canvas::Canvas;
use super::hits::{around, sampled};
use super::serial::{serial, SCALES};
use super::states::states;
use super::toast::{ACTIONS, TEXTS};

/// The smallest rect holding every pixel a live state changes in `at`.
fn action_drawn(t: Toast<'static>, at: Rect) -> Option<Rect> {
    let paint = |t: Toast| Canvas::new(at, 0).painted(|fb| t.draw(fb, at));
    let (plain, live) = (paint(t), states().filter(|s| !s.disabled));
    let all: Vec<_> = live.flat_map(|st| paint(t.state(st)).diff(&plain)).collect();
    let span =
        |f: fn(&(u32, u32)) -> u32| Some((all.iter().map(f).min()?, all.iter().map(f).max()?));
    let ((x0, x1), (y0, y1)) = (span(|p| p.0)?, span(|p| p.1)?);
    Some(Rect { x: x0, y: y0, w: x1 - x0 + 1, h: y1 - y0 + 1 })
}

/// A point where `hit` and the drawn action disagree, among sampled drawn
/// pixels, either side of each of the action's edges, and round `at`.
fn wrong(t: Toast<'static>, at: Rect) -> Option<String> {
    let a = action_drawn(t, at);
    let mut probes: Vec<_> = sampled(t, at).map(|(x, y)| (x as i32, y as i32)).collect();
    probes.extend(around(at));
    if let Some(a) = a {
        let (x0, y0, x1, y1) = (a.x as i32, a.y as i32, (a.x + a.w) as i32, (a.y + a.h) as i32);
        probes.extend((x0 - 1..=x1).flat_map(|x| [(x, y0 - 1), (x, y0), (x, y1 - 1), (x, y1)]));
        probes.extend((y0 - 1..=y1).flat_map(|y| [(x0 - 1, y), (x0, y), (x1 - 1, y), (x1, y)]));
    }
    let bad =
        probes.into_iter().find(|&(x, y)| t.hit(at, x, y) != a.is_some_and(|a| contains(a, x, y)));
    bad.map(|p| format!("{p:?} against the action drawn in {a:?}"))
}

#[test]
fn toast_hit_takes_the_action_it_draws_and_nothing_else() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for (text, action) in TEXTS.into_iter().flat_map(|t| ACTIONS.map(|a| (t, a))) {
            let t = Toast::new(text).action(action);
            for at in boxes(t.size()) {
                let what = |e| format!("{text:?} {action:?} at {q}/4 in {at:?}: {e}");
                fails.extend(wrong(t, at).map(what));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
