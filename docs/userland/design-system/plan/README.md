# Plan, round 2

Phases 1 to 8 built the design system and are done on `feat/toolkit-design-system`. Round 2
carries out [Migration, round 2](../migration-2.md) on the same branch, as phases 9 to 17.

| Phase | Work | Steps |
|---|---|---|
| 9 | `Pointer`, and hover, press and focus in the three widget apps | [Phases 9 and 10](phases-9-10.md) |
| 10 | the version 2 widgets | [Phases 9 and 10](phases-9-10.md) |
| 11 | small apps | [Phases 11 to 13](phases-11-13.md) |
| 12 | File manager, Process Manager's tables, Audio player, Video player | [Phases 11 to 13](phases-11-13.md) |
| 13 | desktop shell | [Phases 11 to 13](phases-11-13.md) |
| 14 | Terminal, Text Editor, Browser | [Phases 14 to 17](phases-14-17.md) |
| 15 | Login, Input probe, the shared helpers, the literal gate | [Phases 14 to 17](phases-14-17.md) |
| 16 | display scale on | [Phases 14 to 17](phases-14-17.md) |
| 17 | retire the dead parts, verify, boot | [Phases 14 to 17](phases-14-17.md) |

## Rules for every step

From `CLAUDE.md`, and from what round 1 learned:

- **One task at a time,** with an entry in the handoff log after each.
- **Code rules:**
  - No file grows by more than 75 lines in one change.
  - `mod.rs` holds declarations only.
  - No `//` comments inside function bodies.
  - Remove what the edit orphans; report pre-existing dead code rather than deleting it.
- **Commits:** `type(scope): imperative summary`, with a body that says why, ending with the
  session trailer. Push only to `feat/toolkit-design-system`.
- **Subagents** do not commit, stage, sign, enroll, boot QEMU, or edit `.md`, `.keys` or
  `nonos-data`. Every edit they make is audited before it is committed.
- **Before each commit:**
  - `cargo check --release --target ../x86_64-nonos-user.json -Zbuild-std=core,alloc
    -Zbuild-std-features=compiler-builtins-mem` for each touched crate; warnings must not exceed
    the baseline.
  - The app's proofs crate, and `theme_proofs` when the toolkit changed.
  - `python3 -I tools/nix/inputs.py --check`, run after staging, since it sees only tracked
    files.
  - `python3 scripts/check_ui_literals.py`, `check_allows.py` and `check_stubs.py`, without
    `-I`, since they import `scripts/gate.py`.
- **Tests are never weakened to pass.** A failing readability or bounds proof is fixed in the
  toolkit or the app.
- **Each app step:**
  - deletes the private widget files it replaces;
  - wires hover, press and focus for its controls;
  - adds its UI folder to `SCOPES` in `check_ui_literals.py` once it holds no literals;
  - records UI lines before and after in its commit body.
- **Steps that need a boot** say so. The boot runs on the owner's machine:
  - `make nonos-mk-run` alone, twice;
  - then check that the staged `kernel.bin` carries the changed capsule.

## Order of risk

Phases 9 and 10 change only the toolkit, and their proofs run on the host. Phases 11 and 12
change one app at a time. Phases 13, 16 and 17 need a boot to believe, so each lands in commits
that can be reverted alone.
