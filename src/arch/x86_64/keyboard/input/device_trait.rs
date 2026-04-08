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

use super::types::{DeviceId, InputEvent};

pub const MAX_INPUT_DEVICES: usize = 16;

pub trait InputDevice: Send + Sync {
    fn device_id(&self) -> DeviceId;
    fn name(&self) -> &str;
    fn device_type(&self) -> &'static str;
    fn poll(&self) -> Option<InputEvent>;
    fn is_connected(&self) -> bool;
}
