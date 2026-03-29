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

mod crypto;
mod progress;
mod stages;

use super::state::CryptoScreenState;

pub fn render_crypto_state(state: &CryptoScreenState) {
    crypto::render_blake3(state);
    crypto::render_ed25519(state);
    crypto::render_zk(state);
    stages::render_stages(state);
    progress::render_progress(state);
}

pub fn render_stage_update(stage: u8, running: bool) {
    stages::render_stage_update(stage, running);
}
