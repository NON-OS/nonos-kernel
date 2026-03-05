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

// PQClean expects: void randombytes(uint8_t *buf, size_t n);
// We route to the kernel's RNG via a Rust-exported symbol.

#include <stdint.h>
#include <stddef.h>

extern void nonos_randombytes(uint8_t *buf, size_t n);

void randombytes(uint8_t *buf, size_t n) {
    nonos_randombytes(buf, n);
}
