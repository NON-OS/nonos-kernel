# Design system

The shared look of NONOS apps: one set of theme colours, one list of widgets, and the theme the
person picks reaching every app. An app imports a widget and draws it. It names no colour and does
no drawing arithmetic of its own.

**Status:** built on `feat/toolkit-design-system`: the roles, sizes, 15 widgets, the theme
following, every app in [Migration](migration.md) moved over, and Settings' Theme block, where
the theme and high contrast are chosen. Round 2, which moves every remaining app onto shared
widgets and adds hover, press, focus and scale, is specified below and planned in
[Plan, round 2](plan/README.md). The decision behind it is
[ADR 0001](../../../adr/0001-toolkit-design-system.md).

## Goals

- An app screen is written with shared widgets: `use nonos_toolkit::widgets::{Button, Switch};`.
- A new widget is added once, to the shared list, and then any app can import it.
- Every app follows the theme and the high-contrast setting chosen in Settings.
- Every colour is readable in every theme, and the host proofs say so.

## Not goals, for now

- Themes the person designs. The built-in schemes are what is offered.
- Widgets that keep their own state or call back into the app. The app keeps the state; a widget
  draws it.
- A layout engine. A widget is drawn into a `Rect`; version 1 adds a few rectangle helpers.
- Animation.

## The parts

| Part | What it is | Where | Page |
|---|---|---|---|
| Seeds | the 5 colours that define a theme | `toolkit/src/theme/schemes/`, exists | [Colours](colours.md) |
| Roles | the named colours widgets draw with, worked out from the seeds | `toolkit/src/theme/roles/` | [Colours](colours.md) |
| Sizes and scale | spacing, radii, text sizes, logical to screen pixels | `toolkit/src/design/{size,text_role,scale}.rs` | [Sizes](sizes.md) |
| Widgets | `new`, builder methods, `draw`, `hit` | `toolkit/src/widgets/` | [Widgets](widgets.md), [Widget list](widget-list.md) |
| Theme choice | the setting, carried from Settings to every app | `app_skeleton/src/runner/theme_follow.rs` | [Themes](themes.md) |

## Rules

- An app writes no ARGB literal. Its colours come from `roles()`, through the widgets.
  `scripts/check_ui_literals.py` fails on a new one in the widgets or a migrated app's UI.
- Every widget lives in `nonos_toolkit::widgets`. An app keeps no private widgets.
- A widget's painter and its hit test call the same geometry function, so a click lands on what
  was drawn.
- Text is measured with `measure_ttf`. Nothing is sized by counting characters.
- Toolkit code follows the repository rules: `no_std`, `mod.rs` holds declarations only, no
  comments inside function bodies, and no file grows by more than 75 lines in one change.

## Pages

- [Current state](current-state.md): what exists today, measured, and the defects found.
- [Colours](colours.md): seeds, roles, colour types, readability.
- [Sizes](sizes.md): spacing, radii, text sizes and display scale.
- [Widgets](widgets.md): the widget contract, state and input, text helpers, tests.
- [Widget list](widget-list.md): what version 1 holds and what comes later.
- [Themes](themes.md): how the person's choice reaches every app.
- [Migration](migration.md): the order apps move over, and when the work is done.
- Round 2:
  - [App inventory](app-inventory.md): what each app still draws itself.
  - [Widgets, version 2](widgets-v2.md): Column, Checkbox, Radio, IconButton, Tooltip, Toast,
    Menu, Dialog, Table.
  - [Interaction](interaction.md): hover, press and focus.
  - [Display scale](scaling.md): turning the scale on.
  - [Migration, round 2](migration-2.md): the order, the last screens, the bugs, done when.
  - [Plan, round 2](plan/README.md): phases 9 to 17, step by step.
