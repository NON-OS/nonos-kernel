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

#[repr(C)]
pub struct Lconv {
    pub decimal_point: *const u8, pub thousands_sep: *const u8, pub grouping: *const u8,
    pub int_curr_symbol: *const u8, pub currency_symbol: *const u8, pub mon_decimal_point: *const u8,
    pub mon_thousands_sep: *const u8, pub mon_grouping: *const u8, pub positive_sign: *const u8,
    pub negative_sign: *const u8, pub int_frac_digits: u8, pub frac_digits: u8, pub p_cs_precedes: u8,
    pub p_sep_by_space: u8, pub n_cs_precedes: u8, pub n_sep_by_space: u8, pub p_sign_posn: u8,
    pub n_sign_posn: u8, pub int_p_cs_precedes: u8, pub int_p_sep_by_space: u8, pub int_n_cs_precedes: u8,
    pub int_n_sep_by_space: u8, pub int_p_sign_posn: u8, pub int_n_sign_posn: u8,
}

pub static DECIMAL_POINT: [u8; 2] = [b'.', 0];
pub static EMPTY_STRING: [u8; 1] = [0];
pub static C_LOCALE: [u8; 2] = [b'C', 0];

pub static mut LCONV: Lconv = Lconv {
    decimal_point: DECIMAL_POINT.as_ptr(), thousands_sep: EMPTY_STRING.as_ptr(),
    grouping: EMPTY_STRING.as_ptr(), int_curr_symbol: EMPTY_STRING.as_ptr(),
    currency_symbol: EMPTY_STRING.as_ptr(), mon_decimal_point: EMPTY_STRING.as_ptr(),
    mon_thousands_sep: EMPTY_STRING.as_ptr(), mon_grouping: EMPTY_STRING.as_ptr(),
    positive_sign: EMPTY_STRING.as_ptr(), negative_sign: EMPTY_STRING.as_ptr(),
    int_frac_digits: 127, frac_digits: 127, p_cs_precedes: 127, p_sep_by_space: 127,
    n_cs_precedes: 127, n_sep_by_space: 127, p_sign_posn: 127, n_sign_posn: 127,
    int_p_cs_precedes: 127, int_p_sep_by_space: 127, int_n_cs_precedes: 127,
    int_n_sep_by_space: 127, int_p_sign_posn: 127, int_n_sign_posn: 127,
};
