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

//! Kernel-side bridge used by user-space window managers and GUI daemons.

#![cfg(feature = "ui")]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::ui::event::{Event, WindowEvent, WindowEventKind, publish_event};

pub type GuiCallback = Box<dyn Fn(GuiEvent) + Send + Sync + 'static>;

#[derive(Clone, Debug)]
pub enum GuiEvent {
    WindowCreated { window_id: u32 },
    WindowClosed { window_id: u32 },
    InputEvent(Event),
}

static GUI_CALLBACKS: Mutex<Vec<(u32, GuiCallback)>> = Mutex::new(Vec::new());
static NEXT_GUI_CB_ID: AtomicU32 = AtomicU32::new(1);

pub fn register_gui_callback(cb: GuiCallback) -> u32 {
    let id = NEXT_GUI_CB_ID.fetch_add(1, Ordering::SeqCst);
    let mut reg = GUI_CALLBACKS.lock();
    reg.push((id, cb));
    id
}

pub fn unregister_gui_callback(id: u32) -> bool {
    let mut reg = GUI_CALLBACKS.lock();
    if let Some(pos) = reg.iter().position(|(cid, _)| *cid == id) {
        let _ = reg.swap_remove(pos);
        true
    } else {
        false
    }
}

fn broadcast(ev: GuiEvent) {
    let reg = GUI_CALLBACKS.lock();
    for (_, cb) in reg.iter() {
        (cb)(ev.clone());
    }
}

/// Create window through DesktopManager wrapper. Returns window id on success.
pub fn request_create_window(title: &str, x: i32, y: i32, width: u32, height: u32) -> Result<u32, &'static str> {
    // Delegate to desktop manager implementation
    crate::ui::desktop::create_window(title, x, y, width, height).map(|id| {
        broadcast(GuiEvent::WindowCreated { window_id: id });
        id
    })
}

/// Request window close (sends WindowEvent).
pub fn request_close_window(window_id: u32) -> Result<(), &'static str> {
    let ev = Event::Window(WindowEvent { window_id, kind: WindowEventKind::CloseRequested });
    publish_event(ev).map_err(|_| "event publish failed")
}

/// Post arbitrary UI event.
pub fn post_ui_event(ev: Event) -> Result<(), &'static str> {
    publish_event(ev.clone()).map_err(|_| "event publish failed")?;
    broadcast(GuiEvent::InputEvent(ev));
    Ok(())
}
