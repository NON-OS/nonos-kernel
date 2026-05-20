#!/usr/bin/env bash
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

set -euo pipefail

PIN_FILE='third_party/pqclean/PROVENANCE.md'
EXPECTED='e1ab5c02821be40fd9f73839c0817b9adca212f1'

if [ ! -f "${PIN_FILE}" ]; then
    echo "missing ${PIN_FILE}" >&2
    exit 1
fi

if ! grep -qE "^PQCLEAN_TREE_SHA=${EXPECTED}\$" "${PIN_FILE}"; then
    echo "${PIN_FILE} does not declare PQCLEAN_TREE_SHA=${EXPECTED}" >&2
    exit 1
fi

ACTUAL="$(git rev-parse HEAD:third_party/pqclean 2>/dev/null || true)"

if [ -z "${ACTUAL}" ]; then
    echo "cannot resolve git tree hash for third_party/pqclean" >&2
    exit 1
fi

if [ "${ACTUAL}" != "${EXPECTED}" ]; then
    echo "pqclean tree drift:" >&2
    echo "  expected ${EXPECTED}" >&2
    echo "  actual   ${ACTUAL}" >&2
    echo "if intentional, update PQCLEAN_TREE_SHA in ${PIN_FILE} and this script" >&2
    exit 1
fi

echo "ok pqclean tree hash matches pin (${EXPECTED})"
