pub fn tab_cycle(order: &[usize], current: Option<usize>, shift: bool) -> Option<usize> {
    if order.is_empty() { return None; }
    match current {
        None => {
            if shift { order.last().copied() } else { order.first().copied() }
        }
        Some(cur) => {
            let pos = order.iter().position(|&i| i == cur);
            match pos {
                None => order.first().copied(),
                Some(p) => {
                    if shift {
                        if p == 0 { order.last().copied() } else { Some(order[p - 1]) }
                    } else {
                        if p + 1 >= order.len() { order.first().copied() } else { Some(order[p + 1]) }
                    }
                }
            }
        }
    }
}
