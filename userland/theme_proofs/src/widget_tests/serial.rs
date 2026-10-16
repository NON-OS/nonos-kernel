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

//! The toolkit's live theme and display scale are globals that every widget
//! reads, so the widget proofs take one lock before touching either.

use std::sync::{Mutex, MutexGuard, PoisonError};

use nonos_policy_proto::theme_labels::THEME_LABELS;
use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::theme::store::replace;
use nonos_toolkit::theme::{theme_of, Theme, SCHEMES};

static GLOBALS: Mutex<()> = Mutex::new(());

/// The display scales the proofs draw at, in quarters: 1x, 1.25x and 2x.
pub(crate) const SCALES: [u32; 3] = [4, 5, 8];

/// Takes the lock, with the default theme and 1x scale in force. A test that
/// failed while holding it does not stop the rest from running.
pub(crate) fn serial() -> MutexGuard<'static, ()> {
    let guard = GLOBALS.lock().unwrap_or_else(PoisonError::into_inner);
    set_scale(SCALES[0]);
    replace(theme_of(0, false));
    guard
}

/// Every scheme in the toolkit's table, then the high contrast override, by name.
pub(crate) fn every_theme() -> Vec<(String, Theme)> {
    let label = |i: usize| THEME_LABELS.get(i).and_then(|l| core::str::from_utf8(l).ok());
    let name = |i: usize| label(i).unwrap_or("unlabelled").to_string();
    let mut all: Vec<(String, Theme)> =
        (0..SCHEMES.len()).map(|i| (name(i), theme_of(i as u8, false))).collect();
    all.push(("high contrast".to_string(), theme_of(0, true)));
    all
}

/// The scales inks are read at: 1x and 2x. Colour does not change with scale,
/// so the 1.25x the bounds proofs add is left out to keep the run short.
const READ_SCALES: [u32; 2] = [4, 8];

/// Runs `check` once per theme with that theme in force, at each reading scale.
pub(crate) fn per_theme(mut check: impl FnMut(&str)) {
    for (name, theme) in every_theme() {
        replace(theme);
        for q in READ_SCALES {
            set_scale(q);
            check(&format!("{name} at {q}/4"));
        }
    }
    set_scale(SCALES[0]);
    replace(theme_of(0, false));
}
