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

use core::sync::atomic::AtomicBool;
use spin::Mutex;
use super::controller::Controller;
use super::keyboard::{Keyboard, ScanCodeDecoder};
use super::mouse::Mouse;

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static CONTROLLER: Mutex<Controller> = Mutex::new(Controller::new());
pub static KEYBOARD: Mutex<Keyboard> = Mutex::new(Keyboard::new());
pub static MOUSE: Mutex<Mouse> = Mutex::new(Mouse::new());
pub static DECODER: Mutex<ScanCodeDecoder> = Mutex::new(ScanCodeDecoder::new());
