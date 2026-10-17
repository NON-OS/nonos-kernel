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

//! One shape for every widget, so a proof is written once and run over all.

use nonos_toolkit::widgets::Dialog;
use nonos_toolkit::widgets::IconButton;
use nonos_toolkit::widgets::Menu;
use nonos_toolkit::widgets::Toast;
use nonos_toolkit::widgets::Tooltip;
use nonos_toolkit::widgets::{
    Button, Card, Checkbox, Field, Label, NavItem, Pill, Progress, Radio, Rect, Row, SectionHeader,
    Slider, State, Surface, Switch, Tabs,
};

use super::boxes::boxes;

/// What the proofs need of a widget: its state, size and draw.
pub(crate) trait Widget: Copy {
    /// The widget in state `s`.
    fn with(self, s: State) -> Self;
    /// Its preferred size.
    fn pref(&self) -> (u32, u32);
    /// Paints it in `at`.
    fn paint(&self, fb: &mut impl Surface, at: Rect);
    /// The box its inks are read in: its own size.
    fn read_box(&self) -> Rect {
        boxes(self.pref())[0]
    }
}

macro_rules! widget {
    ($($t:ty),*) => {$(
        impl Widget for $t {
            fn with(self, s: State) -> Self { self.state(s) }
            fn pref(&self) -> (u32, u32) { self.size() }
            fn paint(&self, fb: &mut impl Surface, at: Rect) { self.draw(fb, at) }
        }
    )*};
}

widget!(Button<'_>, Card<'_>, Field<'_>, Label<'_>, NavItem<'_>, Pill<'_>, Progress, Row<'_>);
widget!(SectionHeader<'_>, Slider, Switch, Tabs<'_>, Checkbox<'_>, Radio<'_>);
widget!(IconButton<'_>, Tooltip<'_>, Toast<'_>, Menu<'_>, Dialog<'_>);
