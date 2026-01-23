// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod controller;
mod keyboard;
mod mouse;

pub use controller::Controller;
pub use keyboard::{Keyboard, ScanCodeDecoder, ScanCodeSet, ScanCodeState, TypematicConfig};
pub use mouse::{Mouse, MousePacket, MouseType, Resolution};
pub use super::error::{Ps2Error, Ps2Result};

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::types::LedState;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static CONTROLLER: Mutex<Controller> = Mutex::new(Controller::new());
static KEYBOARD: Mutex<Keyboard> = Mutex::new(Keyboard::new());
static MOUSE: Mutex<Mouse> = Mutex::new(Mouse::new());
static DECODER: Mutex<ScanCodeDecoder> = Mutex::new(ScanCodeDecoder::new());

pub fn init() -> Ps2Result<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(Ps2Error::AlreadyInitialized);
    }

    let mut controller = CONTROLLER.lock();
    controller.init()?;

    {
        let mut keyboard = KEYBOARD.lock();
        if let Err(e) = keyboard.init(&controller) {
            if !controller.port2_working() {
                INITIALIZED.store(false, Ordering::SeqCst);
                return Err(e);
            }
        }
    }

    if controller.port2_working() {
        let mut mouse = MOUSE.lock();
        let _ = mouse.init(&controller);
    }

    Ok(())
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub fn has_keyboard() -> bool {
    KEYBOARD.lock().is_detected()
}

pub fn has_mouse() -> bool {
    MOUSE.lock().is_detected()
}

pub fn set_leds(leds: LedState) -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    let controller = CONTROLLER.lock();
    let keyboard = KEYBOARD.lock();
    keyboard.set_leds(&controller, leds)
}

pub fn set_typematic(config: TypematicConfig) -> Ps2Result<()> {
    if !is_initialized() {
        return Err(Ps2Error::NotInitialized);
    }
    let controller = CONTROLLER.lock();
    let keyboard = KEYBOARD.lock();
    keyboard.set_typematic(&controller, config)
}

pub fn handle_interrupt() {
    let controller = CONTROLLER.lock();

    while controller.has_data() {
        let data = controller.read_data_nowait();

        if controller.is_mouse_data() {
            let mut mouse = MOUSE.lock();
            if let Some(packet) = mouse.process_byte(data) {
                handle_mouse_packet(packet);
            }
        } else {
            let mut decoder = DECODER.lock();
            if let Some((code, released, extended)) = decoder.decode(data) {
                handle_key_event(code, released, extended);
            }
        }
    }
}

fn handle_key_event(code: u8, released: bool, extended: bool) {
    use super::input;
    use super::keymap;

    let event = input::KeyEvent {
        scan_code: code,
        pressed: !released,
        modifiers: input::Modifiers::NONE,
        repeat_count: 0,
    };

    let kind = if released {
        input::InputEventKind::KeyRelease(event)
    } else {
        input::InputEventKind::KeyPress(event)
    };

    let _ = input::push_event(input::InputEvent::new(kind));

    keymap::update_modifiers(code, released, extended);
}

fn handle_mouse_packet(packet: MousePacket) {
    use super::input;

    if packet.dx != 0 || packet.dy != 0 {
        let event = input::MouseMoveEvent {
            dx: packet.dx,
            dy: packet.dy,
            abs_x: None,
            abs_y: None,
        };
        let _ = input::push_event(input::InputEvent::new(
            input::InputEventKind::MouseMove(event),
        ));
    }

    if packet.dz != 0 {
        let event = input::MouseScrollEvent {
            delta_y: packet.dz,
            delta_x: 0,
        };
        let _ = input::push_event(input::InputEvent::new(
            input::InputEventKind::MouseScroll(event),
        ));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ps2Stats {
    pub initialized: bool,
    pub keyboard_detected: bool,
    pub mouse_detected: bool,
    pub mouse_type: Option<MouseType>,
    pub scancode_set: Option<ScanCodeSet>,
}

pub fn get_stats() -> Ps2Stats {
    let keyboard = KEYBOARD.lock();
    let mouse = MOUSE.lock();

    Ps2Stats {
        initialized: is_initialized(),
        keyboard_detected: keyboard.is_detected(),
        mouse_detected: mouse.is_detected(),
        mouse_type: if mouse.is_detected() { Some(mouse.mouse_type()) } else { None },
        scancode_set: if keyboard.is_detected() { Some(keyboard.scancode_set()) } else { None },
    }
}
