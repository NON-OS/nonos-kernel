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

pub mod file;
pub mod printf;
pub mod scanf;
pub mod fopen;

pub use file::{FILE, stdin, stdout, stderr, fflush, feof, ferror, clearerr, fileno};
pub use printf::{printf, fprintf, sprintf, snprintf, vprintf, vfprintf, vsprintf, vsnprintf};
pub use scanf::{scanf, fscanf, sscanf};
pub use fopen::{fopen, fclose, fread, fwrite, fseek, ftell, rewind, fgetc, fputc, fgets, fputs};
