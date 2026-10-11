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

use alloc::string::String;
use alloc::vec::Vec;

mod chrome;
mod chrome_new;
mod fit_text;
mod loading;
mod mark;
mod new;
mod note_history;
mod tell;
mod types;

pub use chrome::{Chrome, Origin, PaintTrack};
pub use types::{ProxyConfig, View};

/* Everything the browser holds: `ui` is the chrome (address bar, focus,
 * history), `track` what changed on screen since the last paint. */
pub struct State {
    pub status: String,
    pub pending_nav: Option<String>,
    pub document: Option<crate::browser::layout::doc::RenderDocument>,
    pub box_doc: Option<crate::browser::layout::boxmodel::BoxDocument>,
    pub page_dom: Option<crate::browser::dom::Dom>,
    pub world: Option<crate::browser::js::World>,
    /* The page's QuickJS engine; it holds a pointer into `page_dom`, so a
     * navigation drops it before replacing the DOM. */
    pub engine: Option<nonos_qjs::Engine>,
    pub settings_open: bool,
    /* The focused page form field, only while the page has the keyboard. */
    pub focus: Option<usize>,
    pub pending_post: Option<String>,
    pub scroll: u32,
    pub sockets_port: u32,
    pub view: View,
    pub fetch: Option<crate::browser::fetch::types::Fetch>,
    pub base: Option<crate::browser::url::Url>,
    pub redirect_count: u8,
    /* The next commit rewrites the current history entry (reload, redirect
     * after a back/forward step) instead of adding one. */
    pub suppress_history_push: bool,
    pub retries: u8,
    /* The address a page offering the Anyone network failed at, which
     * about:anyone loads again over Anyone (`fetch::exits`). */
    pub anyone_retry: Option<String>,
    pub proxy: Option<ProxyConfig>,
    pub images: crate::browser::image::Store,
    pub image_queue: Vec<String>,
    pub img_turn: bool,
    pub keep: Option<crate::browser::fetch::KeptConn>,
    pub font_queue: Vec<(u32, String)>,
    pub font_seen: Vec<u32>,
    /* Page area size: the layout's content rect, from the paint surface. */
    pub viewport_w: u32,
    pub viewport_h: u32,
    /* Where the last paint put the toolbar and the page, and whether it
     * showed the start page there, or any page the window draws itself
     * over the tab's own; events and damage read these, so they find what
     * that paint drew. */
    pub layout: crate::browser::ui::layout::Layout,
    pub on_start: bool,
    pub on_own: bool,
    /* The tab group this tab is in, if any. */
    pub group: Option<u8>,
    /* The committed page's title, which the bookmark star files it under,
     * and the address a load just committed, for the window's visit log. */
    pub title: String,
    pub visited: Option<String>,
    /* A response the engine cannot show, for the window to save. */
    pub downloaded: Option<crate::browser::shell::types::Downloaded>,
    pub css_queue: Vec<String>,
    /* How long the first paint still waits for those sheets. */
    pub style_hold: crate::browser::fetch::StyleHold,
    pub page_css: String,
    /* External scripts to fetch, each with its place in the page's order. */
    pub script_queue: Vec<(u32, String)>,
    pub css_cache: Option<crate::browser::css::CssCache>,
    /* Sub-resource fetches side by side; `fetch` is the navigation's own. */
    pub pool: crate::browser::fetch::Pool,
    pub ui: Chrome,
    pub track: PaintTrack,
    /* What of the page lives in process globals, while the tab is out of
     * view (`tab_scope`). */
    pub scope: crate::browser::tab_scope::Scope,
}
