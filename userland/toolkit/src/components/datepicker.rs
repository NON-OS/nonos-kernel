#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalendarDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

pub fn is_valid_date(d: CalendarDate) -> bool {
    if d.month == 0 || d.month > 12 || d.day == 0 {
        return false;
    }
    let max = match d.month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 29,
        _ => 0,
    };
    d.day <= max
}
