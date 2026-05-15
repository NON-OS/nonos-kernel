#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusFlags {
    pub network_up: bool,
    pub battery_pct: u8,
    pub alerts: u8,
}

impl StatusFlags {
    pub fn battery_clamped(mut self) -> Self {
        if self.battery_pct > 100 {
            self.battery_pct = 100;
        }
        self
    }
}
