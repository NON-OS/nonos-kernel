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
pub enum ScanCodeState {
    Normal,
    Extended,
    ExtendedRelease,
    Pause(u8),
}

pub struct ScanCodeDecoder {
    state: ScanCodeState,
}

impl ScanCodeDecoder {
    pub const fn new() -> Self {
        Self {
            state: ScanCodeState::Normal,
        }
    }

    pub fn decode(&mut self, byte: u8) -> Option<(u8, bool, bool)> {
        match self.state {
            ScanCodeState::Normal => {
                match byte {
                    0xE0 => {
                        self.state = ScanCodeState::Extended;
                        None
                    }
                    0xE1 => {
                        self.state = ScanCodeState::Pause(0);
                        None
                    }
                    _ => {
                        let released = (byte & 0x80) != 0;
                        let code = byte & 0x7F;
                        Some((code, released, false))
                    }
                }
            }
            ScanCodeState::Extended => {
                let released = (byte & 0x80) != 0;
                let code = byte & 0x7F;
                self.state = ScanCodeState::Normal;
                Some((code, released, true))
            }
            ScanCodeState::ExtendedRelease => {
                self.state = ScanCodeState::Normal;
                Some((byte & 0x7F, true, true))
            }
            ScanCodeState::Pause(count) => {
                if count < 5 {
                    self.state = ScanCodeState::Pause(count + 1);
                    None
                } else {
                    self.state = ScanCodeState::Normal;
                    Some((0x45, false, true))
                }
            }
        }
    }

    pub fn reset(&mut self) {
        self.state = ScanCodeState::Normal;
    }
}

impl Default for ScanCodeDecoder {
    fn default() -> Self {
        Self::new()
    }
}
