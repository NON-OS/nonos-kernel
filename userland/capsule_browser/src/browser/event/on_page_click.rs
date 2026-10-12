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

use nonos_app_skeleton::{EventOutcome, InputEvent};

use nonos_qjs::Press;

use crate::browser::dom::Dom;
use crate::browser::omnibox::{focus_after, Region};
use crate::browser::state::State;

use super::field_at::{field_at, Field};

/* A click on the page. Script listeners see it first; only a listener that
 * calls preventDefault stops the default action, so a page that merely
 * listens for clicks (most of the web does) keeps working links and fields.
 * Then a checkbox or radio button is checked, a form field takes focus, a
 * submit control submits, a label passes the click to its control, and a
 * link is followed. The link is read before the listeners run, as the
 * default action belongs to the element that was clicked. Before the
 * click the page hears the press itself (page_input::page_press), and a
 * press on no element lands on the body. */
pub fn on_page_click(state: &mut State, event: InputEvent) -> EventOutcome {
    let y = event.y;
    let link = super::link_under::link_under(state, event.x, y);
    let scroll = state.scroll as i32;
    let hit = state.box_doc.as_ref().and_then(|b| b.hit_node(event.x, y, scroll));
    let node = hit.or_else(|| super::page_input::body(state));
    let mut field = None;
    let mut prevented = false;
    if let Some(node) = node {
        let press = super::page_input::press_at(&event, event.x, y);
        super::page_input::page_press(state, node, &press);
        let click = Press { buttons: 0, ..press };
        match click_on(state, node, true, &click) {
            Clicked::Done => {
                state.focus_page(None);
                return EventOutcome::Repaint;
            }
            Clicked::Field(id) => field = Some(id),
            Clicked::Prevented => prevented = true,
            Clicked::Nothing => {}
        }
    }
    let (_, field) = focus_after(Region::Page, field, state.ui.kbd);
    state.focus_page(field);
    match link {
        Some(href) if !prevented && field.is_none() => {
            super::follow_link::follow_link(state, &href)
        }
        _ => EventOutcome::Idle,
    }
}

/* What a click on one node came to. */
enum Clicked {
    /* Its action is taken (a box checked, a form sent, a script went
     * elsewhere): nothing more of this click. */
    Done,
    /* A text field, which takes the keyboard. */
    Field(usize),
    /* A listener cancelled it. */
    Prevented,
    Nothing,
}

/* The page's listeners, then the click's own action on `node`. A checkbox
 * or radio button changes before the listeners run, and back if one of
 * them cancels the click (toggle_field). A click on a label that its
 * listeners left alone is then a click on its control (label_for), with
 * the same events as a click there, once: `outer` is false for that one.
 * `press` is where the click was, which the click carries and an image
 * submit button sends. */
fn click_on(state: &mut State, node: usize, outer: bool, press: &Press) -> Clicked {
    let toggled = match state.page_dom.as_ref().map(|dom| field_at(dom, node)) {
        Some(Field::Toggle(id)) => super::toggle_field::before_click(state, id).map(|p| (id, p)),
        _ => None,
    };
    let click = super::js_click::js_click(state, node, press);
    let was_toggle = toggled.is_some();
    if let Some((id, prior)) = toggled {
        super::toggle_field::after_click(state, id, prior, click.prevented);
    }
    if was_toggle || (click.fired && state.pending_nav.is_some()) {
        return Clicked::Done;
    }
    if click.prevented {
        return Clicked::Prevented;
    }
    let Some(dom) = state.page_dom.as_ref() else { return Clicked::Nothing };
    match field_at(dom, node) {
        Field::Edit(id) => Clicked::Field(id),
        Field::Select(id) => {
            super::select_open::open_select(state, id);
            Clicked::Done
        }
        Field::Submit(id) => {
            let at = image_point(dom, id, press, state.scroll);
            super::submit_form::submit_form(state, id, at);
            Clicked::Done
        }
        _ => match super::label_for::label_control(dom, node) {
            Some(control) if outer && control != node => click_on(state, control, false, press),
            _ => Clicked::Nothing,
        },
    }
}

/* Where on an image submit button `id` the press was, from the image's
 * top left corner, which the form sends as name.x and name.y. None for
 * any other button. */
fn image_point(dom: &Dom, id: usize, press: &Press, scroll: u32) -> Option<(i32, i32)> {
    let n = dom.nodes.get(id)?;
    if n.tag != "input" || !n.attr("type").is_some_and(|t| t.eq_ignore_ascii_case("image")) {
        return None;
    }
    let x = press.x - dom.box_of(id, 0);
    let y = press.y + scroll as i32 - dom.box_of(id, 1);
    Some((x.max(0), y.max(0)))
}
