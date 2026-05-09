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

#include "randombytes.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int randombytes(uint8_t *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        return -1;
    }
    size_t got = 0;
    while (got < n) {
        size_t r = fread(buf + got, 1, n - got, f);
        if (r == 0) {
            fclose(f);
            return -1;
        }
        got += r;
    }
    fclose(f);
    return 0;
}
