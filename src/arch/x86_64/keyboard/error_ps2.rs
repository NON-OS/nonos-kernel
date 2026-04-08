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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ps2Error {
    NotInitialized, AlreadyInitialized, ControllerNotFound, Timeout, SelfTestFailed,
    Port1TestFailed, Port2TestFailed, KeyboardNotDetected, MouseNotDetected, SendFailed,
    InvalidResponse, BufferOverrun, ParityError, GeneralError,
}

impl Ps2Error {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "PS/2 not initialized", Self::AlreadyInitialized => "PS/2 already initialized",
            Self::ControllerNotFound => "PS/2 controller not found", Self::Timeout => "PS/2 operation timed out",
            Self::SelfTestFailed => "PS/2 self-test failed", Self::Port1TestFailed => "PS/2 port 1 test failed",
            Self::Port2TestFailed => "PS/2 port 2 test failed", Self::KeyboardNotDetected => "PS/2 keyboard not detected",
            Self::MouseNotDetected => "PS/2 mouse not detected", Self::SendFailed => "PS/2 send command failed",
            Self::InvalidResponse => "PS/2 invalid response", Self::BufferOverrun => "PS/2 buffer overrun",
            Self::ParityError => "PS/2 parity error", Self::GeneralError => "PS/2 general error",
        }
    }
}

pub type Ps2Result<T> = Result<T, Ps2Error>;
