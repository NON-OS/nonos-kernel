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

use crate::display::right_panel::{
    render_crypto_state, render_progress_bar, CryptoDisplay, RightPanelLayout,
};

#[derive(Clone, Copy)]
pub struct ScreenState {
    pub kernel_hash: Option<[u8; 32]>,
    pub signature_valid: Option<bool>,
    pub zk_valid: Option<bool>,
    pub tpm_measured: bool,
    pub progress: u8,
}

impl Default for ScreenState {
    fn default() -> Self {
        Self {
            kernel_hash: None,
            signature_valid: None,
            zk_valid: None,
            tpm_measured: false,
            progress: 0,
        }
    }
}

pub fn update_screen_state(state: &ScreenState) {
    let layout = RightPanelLayout::compute();

    let display = CryptoDisplay {
        kernel_hash: state.kernel_hash.as_ref(),
        signature_valid: state.signature_valid,
        zk_valid: state.zk_valid,
        tpm_measured: state.tpm_measured,
    };

    render_crypto_state(&layout, &display);
    render_progress_bar(&layout, state.progress);
}
