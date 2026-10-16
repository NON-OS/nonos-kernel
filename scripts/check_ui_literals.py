#!/usr/bin/env python3
# NONOS Operating System
# Copyright (C) 2026 NONOS Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""No colour literal may be added to the shared widgets or a migrated app's UI.

A widget or a migrated screen takes its colours from the theme's roles, so a
theme chosen in Settings reaches it. An ARGB literal there is a colour no theme
can change. Every one left is listed against scripts/baselines/ui-literals.txt,
a list that may only shrink. An app joins SCOPES when it moves to the roles.
"""

import re
import sys
import tempfile
from pathlib import Path

import gate

BASELINE = Path("scripts/baselines/ui-literals.txt")

# The shared widgets, then each migrated app's drawing code. A small app is
# scanned whole; a large one only where it draws.
SCOPES = [
    "userland/toolkit/src/widgets",
    "userland/capsule_settings/src/settings/ui",
    "userland/capsule_app_store/src",
    "userland/capsule_process_manager/src",
    "userland/capsule_about/src",
    "userland/capsule_snake/src",
    "userland/capsule_hello/src",
    "userland/capsule_qrgen/src",
    "userland/capsule_mdview/src",
    "userland/capsule_prove/src",
    "userland/capsule_gui_demo/src",
    "userland/capsule_egui_proof/src",
    "userland/capsule_calculator/src",
    "userland/capsule_clock/src",
    "userland/capsule_file_manager/src",
    "userland/capsule_game_2048/src",
    "userland/capsule_gui_proof/src",
    "userland/capsule_image_viewer/src",
    "userland/capsule_input_proof/src",
    "userland/capsule_video_player/src/ui",
    "userland/capsule_audio_player/src/ui",
    "userland/capsule_text_editor/src/editor",
    "userland/capsule_terminal/src/paint",
    "userland/capsule_browser/src/browser/paint",
    "userland/capsule_desktop_shell/src/render",
]

# The named themes the Browser, the Text Editor and the Terminal keep beside
# System are fixed colours by choice, and a window's id in its manifest is a
# tag, not a colour.
SKIP = (
    "userland/capsule_browser/src/browser/paint/tokens/",
    "userland/capsule_text_editor/src/editor/theme/",
    "/manifest.rs",
)

ARGB = re.compile(r"\b0x(?:_?[0-9A-Fa-f]){8}\b")
COMMENT = re.compile(r"^\s*(//|/\*|\*)")


def sites(root):
    out = []
    for scope in SCOPES:
        for p in sorted((root / scope).rglob("*.rs")):
            rel = str(p.relative_to(root))
            if any(s in rel for s in SKIP):
                continue
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if not COMMENT.match(line) and ARGB.search(line):
                    out.append(f"{rel}:{n}")
    return out


def self_test():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        widgets = root / SCOPES[0]
        widgets.mkdir(parents=True)
        (widgets / "decoy.rs").write_text("// 0xFF00_0000 in a comment\nconst INK: u32 = 0xFF00_0000;\n")
        (widgets / "manifest.rs").write_text("const WINDOW_ID: u32 = 0x4845_4C4F;\n")
        found = sites(root)
        if found != [f"{SCOPES[0]}/decoy.rs:2"]:
            print(f"ui-literals: self-test failed, found {found}")
            return 1
    print("ui-literals: self-test passed, the decoy was reported")
    return 0


def main():
    args = gate.parser(__doc__).parse_args()
    if args.self_test:
        return self_test()
    return gate.run("ui-literals", "new colour literal at", sites, BASELINE, args)


if __name__ == "__main__":
    sys.exit(main())
