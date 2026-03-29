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

use crate::graphics::{framebuffer, desktop, cursor, window};
use crate::sys::{serial, clock};
use crate::entry::desktop_loop;
use crate::input;
use core::arch::asm;

pub fn run_desktop() -> ! {
    serial::println(b"[NONOS] Desktop loop starting");
    let (mut old_mx, mut old_my) = input::mouse_position_unified();
    framebuffer::double_buffer::disable();
    cursor::draw(old_mx, old_my);
    framebuffer::double_buffer::enable();
    let mut last_clock = clock::unix_ms();
    loop {
        handle_dialogs();
        desktop_loop::handle_keyboard_input();
        desktop_loop::handle_mouse_input(&mut old_mx, &mut old_my);
        crate::network::poll_network();
        crate::apps::ecosystem::browser::poll_navigation();
        check_redraws();
        do_redraw(&mut old_mx, &mut old_my);
        update_clock(&mut last_clock);
        for _ in 0..100 { unsafe { asm!("pause", options(nomem, nostack)); } }
    }
}

fn check_redraws() {
    if window::settings::take_background_changed() { desktop_loop::set_needs_redraw(); }
    if window::ecosystem::state::take_content_changed() { desktop_loop::set_needs_redraw(); }
}

fn do_redraw(mx: &mut i32, my: &mut i32) {
    unsafe {
        if desktop_loop::NEEDS_REDRAW {
            desktop::redraw_background();
            window::draw_all();
            window::context_menu::draw();
            cursor::draw(*mx, *my);
            framebuffer::swap_buffers();
            desktop_loop::NEEDS_REDRAW = false;
        }
    }
}

fn update_clock(last: &mut u64) {
    let now = clock::unix_ms();
    if now >= *last + 1000 {
        *last = now;
        desktop::update_clock();
        desktop_loop::set_needs_redraw();
    }
}

pub fn handle_dialogs() {
    if !window::is_dialog_active() { return; }
    let result = window::get_dialog_result();
    if result == window::dialog_result::RESULT_NONE { return; }
    if result == window::dialog_result::RESULT_OK {
        let text = window::get_dialog_input_text();
        if !text.is_empty() { process_dialog_input(text); }
    }
    window::close_dialog();
    desktop_loop::set_needs_redraw();
}

fn process_dialog_input(text: &str) {
    let cb = window::get_dialog_input_callback();
    match cb {
        x if x == window::dialog_callback::INPUT_CB_DESKTOP_NEW_FOLDER => { desktop::create_desktop_folder(text); }
        x if x == window::dialog_callback::INPUT_CB_DESKTOP_NEW_FILE => { desktop::create_desktop_file(text); }
        x if x == window::dialog_callback::INPUT_CB_FM_NEW_FOLDER => { let _ = window::fm_create_folder(text); }
        _ => {}
    }
}
