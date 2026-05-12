# Wallpaper Minimal Next Patch Execution

Status: in-progress
Scope: minimal patch set only
Date: 2026-05-12

## Goal
Close the wallpaper proof gap without scope expansion.

## Patch Set

1. Add canonical smoke harness at `nonos-ci/wallpaper_round_trip.sh`.
2. Keep wallpaper smoke output deterministic with exact success markers.
3. Remove active legacy graphics or desktop_loop references from:
   - `src/entry/context.rs`
   - `src/entry/desktop_loop/menu_actions.rs`
   - `src/entry/desktop_loop/mouse.rs`
   - `src/entry/desktop_loop/keyboard.rs`
   - `src/test/runner.rs`
4. Add readobj-based wallpaper ELF entry-point check in static gates.

## Required Success Marker Sequence

- `[wallpaper] display ok`
- `[wallpaper] surface created`
- `[wallpaper] surface filled`
- `[wallpaper] present ok`
- `[wallpaper] PASS`

## Verification Commands

1. `bash -n nonos-ci/run-static-checks.sh`
2. `./nonos-ci/run-static-checks.sh`
3. `./nonos-ci/wallpaper_round_trip.sh`
4. `rg -n "crate::graphics|desktop_loop" src/entry src/test/runner.rs`

## Rollback

- Revert only the touched files in this runbook.
- Do not revert unrelated branch work.
