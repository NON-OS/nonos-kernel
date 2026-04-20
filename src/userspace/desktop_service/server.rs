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

pub fn run_desktop_manager() -> ! {
    crate::sys::boot_log::ok("DESKTOP", "Initializing desktop manager");

    init_graphics_system();
    crate::sys::boot_log::ok("DESKTOP", "Graphics initialized");

    crate::services::registry::register_endpoint_simple("desktop", 1007, 12);
    crate::sys::boot_log::ok("DESKTOP", "Service ready");

    desktop_loop()
}

fn init_graphics_system() {
    super::graphics_manager::initialize_graphics();
}

fn desktop_loop() -> ! {
    let mut frame_count = 0u64;
    let mut last_fps_time = crate::time::current_time_ms();

    loop {
        let start_time = crate::time::current_time_ms();

        handle_input_events();
        update_desktop();
        render_frame();

        frame_count += 1;

        if frame_count % 60 == 0 {
            let current_time = crate::time::current_time_ms();
            let elapsed = current_time - last_fps_time;
            if elapsed > 0 {
                let fps = (60 * 1000) / elapsed;
                if frame_count % 600 == 0 {
                    crate::sys::serial::print(b"[DESKTOP] FPS: ");
                    crate::sys::serial::print_dec(fps);
                    crate::sys::serial::println(b"");
                }
            }
            last_fps_time = current_time;
        }

        let frame_time = crate::time::current_time_ms() - start_time;
        if frame_time < 16 {
            crate::arch::x86_64::asm::sleep_ms((16 - frame_time) as u32);
        }

        crate::sched::yield_now();
    }
}

fn handle_input_events() {
    super::event_handler::process_keyboard_events();
    super::event_handler::process_mouse_events();
}

fn update_desktop() {
    super::graphics_manager::update_animations();
    super::graphics_manager::update_clock();
}

fn render_frame() {
    super::graphics_manager::render_desktop();
}