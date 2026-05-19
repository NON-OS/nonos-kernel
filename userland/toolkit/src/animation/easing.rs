pub const UNIT: u16 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Curve {
    Linear,
    EaseIn,
    EaseOut,
    EaseInOut,
}

pub fn apply(curve: Curve, t: u16) -> u16 {
    let t = t.min(UNIT) as u32;
    let u = UNIT as u32;
    match curve {
        Curve::Linear => t as u16,
        Curve::EaseIn => ((t * t) / u) as u16,
        Curve::EaseOut => (u - (((u - t) * (u - t)) / u)) as u16,
        Curve::EaseInOut => {
            if t <= (u / 2) {
                ((2 * t * t) / u) as u16
            } else {
                let d = u - t;
                (u - ((2 * d * d) / u)) as u16
            }
        }
    }
}
