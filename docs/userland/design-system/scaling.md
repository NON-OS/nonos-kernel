# Display scale, turned on

[Sizes](sizes.md) defines the scale: quarters, with 4 for 1×, and `scale().px`, `hair` and
`font`. Version 1 kept it at 4 everywhere. This page is how it gets turned on.

## Today

- The skeleton already works out the display's quarters, to draw the window frame
  (`app_skeleton/src/runner/chrome.rs:86-95`, `QUARTERS`). It never calls the toolkit's
  `set_scale`, though, so widgets draw at 1× inside a frame drawn at 1.5× or 2×.
- 19 `metrics.rs` files hold sizes in screen pixels, used without scaling:
  - About, App Store, Audio player, Calculator, Process Manager, Settings and Snake: one each.
  - Terminal: two.
  - Text Editor: four.
  - The desktop shell: four.
  - Also the installer's, and mdview's layout metrics.
- Only hello and the desktop shell read `scale()`.
- The content area does not grow with the scale: `fit_display` grows a window only by what its
  frame takes (`runner/fit_display.rs:34-80`). An app that scaled its sizes would not fit its
  window.

## The design

1. **One scale per process.** When the skeleton fits the window to the display, it calls
   `set_scale(quarters)`, in the same place it stores `QUARTERS`. Widgets already convert
   through it.
2. **Sizes become logical.** Each app's `metrics.rs` keeps logical numbers. Every use goes
   through `scale().px` or `scale().font`, in the one geometry function that its painter and its
   hit test share. A metric that only one shared widget used goes away with that widget.
3. **The content area scales too.** `fit_display` multiplies the manifest's content size by the
   scale, capped by `WINDOW_FRACTION` as today. A manifest's size is logical from then on.
4. **One switch.** Until every app on the skeleton has logical metrics, the skeleton calls
   `set_scale(4)`. The step that passes the real quarters comes last, in its own commit. That
   makes it one revert if a boot shows a problem.

## What stays

- The boot splash, the installer and the wallet keep their own scale, through
  `nonos_brand::scale`.
- The rule that picks quarters from the panel size stays in `scale_rule::quarters_for`. Its copy
  in `capsule_install/brand/src/scale_rule.rs` is noted, not merged, since the installer runs
  outside the desktop.

## Tests

- Each app's proofs crate, where it has one: its geometry at 4, 5, 6 and 8 quarters stays inside
  the window, and draw and hit still agree.
- The widget proofs already draw at 1×, 1.25× and 2×.
- The switch to real quarters is believed only after a boot, on a 1× panel and on a large one.

## Open

- ❓ Units at the widget boundary. `widgets.md` says `size()` is logical, but `Menu` and `Table`
  return drawing pixels; `Menu::width` takes drawing pixels and `Col::fixed` takes logical ones.
  One rule is settled before phase 16.2.

- ❓ Whether the compositor's half-size canvas for large panels
  (`capsule_desktop_shell/src/state/scale.rs`) should change once apps scale, or stay. This is
  measured on a boot.
