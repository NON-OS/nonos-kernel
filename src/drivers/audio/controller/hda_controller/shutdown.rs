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

use super::super::super::error::AudioError;
use super::super::{corb_rirb, init, stream};
use super::structure::HdAudioController;

impl HdAudioController {
    pub fn shutdown(&self) -> Result<(), AudioError> {
        if self.is_playing() {
            stream::stop_stream(self, self.out_stream);
        }
        corb_rirb::stop_corb(self);
        corb_rirb::stop_rirb(self);
        init::shutdown_controller(self)
    }
}
