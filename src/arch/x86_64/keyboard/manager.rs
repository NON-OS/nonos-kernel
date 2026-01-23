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

use core::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static PS2_PRESENT: AtomicBool = AtomicBool::new(false);
static USB_PRESENT: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err("keyboard already initialized");
    }

    let mut has_keyboard = false;

    if super::ps2::init().is_ok() {
        PS2_PRESENT.store(true, Ordering::Release);
        has_keyboard = true;
    }

    if super::usb::init().is_ok() && super::usb::device_count() > 0 {
        USB_PRESENT.store(true, Ordering::Release);
        has_keyboard = true;
    }

    if !has_keyboard {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err("no keyboards detected");
    }

    Ok(())
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub fn has_ps2() -> bool {
    PS2_PRESENT.load(Ordering::Acquire)
}

pub fn has_usb() -> bool {
    USB_PRESENT.load(Ordering::Acquire)
}

pub fn handle_interrupt() {
    super::ps2::handle_interrupt();
}

pub fn poll_usb() {
    if has_usb() {
        let _ = super::usb::poll();
    }
}
