# Wallpaper Black Screen Investigation Plan (First Principles)

Status: completed (phase 2)
Date: 2026-05-13
Branch: feat/graphics-phase0-truth-map

## Problem

Observed contradiction:
- runtime markers show wallpaper pipeline success (`display ok`, `surface created`, `surface filled`, `present ok`, `PASS`)
- operator still sees black screen

## Hypotheses

1. Pipeline success is real, but rendered content is visually near-black.
2. Pixel-format mismatch could desaturate output, but should still show non-black for high-contrast sentinels.
3. Present path may succeed logically while writing no visible contrast.

## Verification Context

- userspace wallpaper fill color before patch: `0xFF202030` (very dark)
- present syscall path executes and returns success
- smoke logs prove full ordered PASS sequence
- smoke harness defaults to headless QEMU (`-display none`), so no visible window is expected in default smoke mode

## Plan

1. Replace near-black solid fill with high-contrast sentinel pattern.
2. Keep syscall flow and markers unchanged.
3. Re-run wallpaper smoke to ensure PASS remains stable.
4. If still black visually, next phase is pixel-format-aware conversion in kernel present path.

## Phase 2 (Executed)

1. Store framebuffer pixel format in kernel framebuffer state.
2. Convert source ARGB8888 pixels in present path to active framebuffer format (RGB/BGR/RGBX/BGRX).
3. Keep smoke criteria unchanged and rerun harness.

## Execution

- Updated wallpaper fill from near-black solid to bright alternating stripes.
- No harness relaxation.

## Validation

- Run: `nonos-ci/wallpaper_round_trip.sh`
- Expected: ordered wallpaper markers and final harness PASS.

## Visual Debug Mode

1. `WALLPAPER_SMOKE_GUI=1 WALLPAPER_SMOKE_HOLD_ON_PASS=1 nonos-ci/wallpaper_round_trip.sh`
2. This keeps the VM window visible on PASS so framebuffer content can be inspected manually.

## Outcome

- This patch makes successful rendering visually obvious while preserving existing smoke criteria.
- Kernel present path now performs explicit format conversion instead of raw byte copy.
- Smoke validation remains green after conversion.
