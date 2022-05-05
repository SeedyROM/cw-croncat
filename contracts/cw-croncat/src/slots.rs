use crate::traits::IntervalExt;
use cosmwasm_std::Env;
use cron_schedule::Schedule;
pub use cw_croncat_core::types::Interval;
use cw_croncat_core::types::{Boundary, BoundarySpec, SlotType};
use std::str::FromStr;

fn get_next_block_limited(env: Env, boundary: Boundary) -> (u64, SlotType) {
    let current_block_height = env.block.height;

    let next_block_height = if boundary.start.is_some() {
        match boundary.start.unwrap() {
            // Note: Not bothering with time, as that should get handled with the cron situations,
            // and probably throw an error when mixing blocks and cron
            BoundarySpec::Height(id) => {
                if current_block_height < id {
                    // shorthand - remove 1 since it adds 1 later
                    id - 1
                } else {
                    current_block_height
                }
            }
            _ => current_block_height,
        }
    } else {
        current_block_height
    };

    if boundary.end.is_some() {
        match boundary.end.unwrap() {
            BoundarySpec::Height(id) => {
                // stop if passed end height
                if current_block_height > id {
                    return (0, SlotType::Block);
                }
                // we ONLY want to catch if we're passed the end block height
                if next_block_height > id {
                    return (id, SlotType::Block);
                }
            }
            _ => unreachable!(),
        }
    }

    // immediate needs to return this block + 1
    (next_block_height + 1, SlotType::Block)
}

// So either:
// - Boundary specifies a start/end that block offsets can be computed from
// - Block offset will truncate to specific modulo offsets
fn get_next_block_by_offset(env: Env, boundary: Boundary, block: u64) -> (u64, SlotType) {
    let current_block_height = env.block.height;
    let modulo_block = current_block_height.saturating_sub(current_block_height % block) + block;

    let next_block_height = if boundary.start.is_some() {
        match boundary.start.unwrap() {
            // Note: Not bothering with time, as that should get handled with the cron situations,
            // and probably throw an error when mixing blocks and cron
            BoundarySpec::Height(id) => {
                if current_block_height < id {
                    let rem = id % block;
                    if rem > 0 {
                        id.saturating_sub(rem) + block
                    } else {
                        id
                    }
                } else {
                    modulo_block
                }
            }
            _ => modulo_block,
        }
    } else {
        modulo_block
    };

    if boundary.end.is_some() {
        match boundary.end.unwrap() {
            BoundarySpec::Height(id) => {
                let rem = id % block;
                let end_height = if rem > 0 { id.saturating_sub(rem) } else { id };

                // stop if passed end height
                if current_block_height > id {
                    return (0, SlotType::Block);
                }

                // we ONLY want to catch if we're passed the end block height
                if next_block_height > end_height {
                    return (end_height, SlotType::Block);
                }
            }
            _ => unreachable!(),
        }
    }

    (next_block_height, SlotType::Block)
}

impl IntervalExt for Interval {
    fn next(&self, env: Env, boundary: Boundary) -> (u64, SlotType) {
        match self {
            // return the first block within a specific range that can be triggered 1 time.
            Interval::Once => get_next_block_limited(env, boundary),
            // return the first block within a specific range that can be triggered immediately, potentially multiple times.
            Interval::Immediate => get_next_block_limited(env, boundary),
            // return the first block within a specific range that can be triggered 1 or more times based on timestamps.
            // Uses crontab spec
            Interval::Cron(crontab) => {
                let current_block_ts: u64 = env.block.time.nanos();
                // TODO: get current timestamp within boundary
                let current_ts: u64 = if boundary.start.is_some() {
                    let start = boundary.start.unwrap();

                    match start {
                        // Note: Not bothering with height, as that should get handled with the block situations,
                        // and probably throw an error when mixing blocks and cron
                        BoundarySpec::Time(ts) => {
                            if current_block_ts < ts.nanos() {
                                ts.nanos()
                            } else {
                                current_block_ts
                            }
                        }
                        _ => current_block_ts,
                    }
                } else {
                    current_block_ts
                };

                let schedule = Schedule::from_str(crontab.as_str()).unwrap();
                let next_ts = schedule.next_after(&current_ts).unwrap();
                (next_ts, SlotType::Cron)
            }
            // return the block within a specific range that can be triggered 1 or more times based on block heights.
            // Uses block offset (Example: Block(100) will trigger every 100 blocks)
            // So either:
            // - Boundary specifies a start/end that block offsets can be computed from
            // - Block offset will truncate to specific modulo offsets
            Interval::Block(block) => get_next_block_by_offset(env, boundary, *block),
        }
    }
    fn is_valid(&self) -> bool {
        match self {
            Interval::Once => true,
            Interval::Immediate => true,
            Interval::Block(_) => true,
            Interval::Cron(crontab) => {
                let s = Schedule::from_str(crontab);
                s.is_ok()
            }
        }
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_env;

    #[test]
    fn interval_get_next_block_limited() {
        // (input, input, outcome, outcome)
        let cases: Vec<(Interval, Boundary, u64, SlotType)> = vec![
            // Once cases
            (Interval::Once, Boundary { start: None, end: None }, 12346, SlotType::Block),
            (Interval::Once, Boundary { start: Some(BoundarySpec::Height(12348)), end: None }, 12348, SlotType::Block),
            (Interval::Once, Boundary { start: None, end: Some(BoundarySpec::Height(12346)) }, 12346, SlotType::Block),
            (Interval::Once, Boundary { start: None, end: Some(BoundarySpec::Height(12340)) }, 0, SlotType::Block),
            // Immediate cases
            (Interval::Immediate, Boundary { start: None, end: None }, 12346, SlotType::Block),
            (Interval::Immediate, Boundary { start: Some(BoundarySpec::Height(12348)), end: None }, 12348, SlotType::Block),
            (Interval::Immediate, Boundary { start: None, end: Some(BoundarySpec::Height(12346)) }, 12346, SlotType::Block),
            (Interval::Immediate, Boundary { start: None, end: Some(BoundarySpec::Height(12340)) }, 0, SlotType::Block),
        ];
        for (interval, boundary, outcome_block, outcome_slot_kind) in cases.iter() {
            let env = mock_env();
            // CHECK IT!
            let (next_id, slot_kind) = interval.next(env, boundary.clone());
            println!("next_id {:?}, slot_kind {:?}", next_id, slot_kind);
            assert_eq!(outcome_block, &next_id);
            assert_eq!(outcome_slot_kind, &slot_kind);
        }
    }

    #[test]
    fn interval_get_next_block_by_offset() {
        // (input, input, outcome, outcome)
        let cases: Vec<(Interval, Boundary, u64, SlotType)> = vec![
            // strictly modulo cases
            (Interval::Block(1), Boundary { start: None, end: None }, 12346, SlotType::Block),
            (Interval::Block(10), Boundary { start: None, end: None }, 12350, SlotType::Block),
            (Interval::Block(100), Boundary { start: None, end: None }, 12400, SlotType::Block),
            (Interval::Block(1000), Boundary { start: None, end: None }, 13000, SlotType::Block),
            (Interval::Block(10000), Boundary { start: None, end: None }, 20000, SlotType::Block),
            (Interval::Block(100000), Boundary { start: None, end: None }, 100000, SlotType::Block),
            // modulo + boundary start
            (Interval::Block(1), Boundary { start: Some(BoundarySpec::Height(12348)), end: None }, 12348, SlotType::Block),
            (Interval::Block(10), Boundary { start: Some(BoundarySpec::Height(12360)), end: None }, 12360, SlotType::Block),
            (Interval::Block(10), Boundary { start: Some(BoundarySpec::Height(12364)), end: None }, 12370, SlotType::Block),
            (Interval::Block(100), Boundary { start: Some(BoundarySpec::Height(12364)), end: None }, 12400, SlotType::Block),
            // modulo + boundary end
            (Interval::Block(1), Boundary { start: None, end: Some(BoundarySpec::Height(12345)) }, 12345, SlotType::Block),
            (Interval::Block(10), Boundary { start: None, end: Some(BoundarySpec::Height(12355)) }, 12350, SlotType::Block),
            (Interval::Block(100), Boundary { start: None, end: Some(BoundarySpec::Height(12355)) }, 12300, SlotType::Block),
            (Interval::Block(100), Boundary { start: None, end: Some(BoundarySpec::Height(12300)) }, 0, SlotType::Block),
        ];
        for (interval, boundary, outcome_block, outcome_slot_kind) in cases.iter() {
            let env = mock_env();
            // CHECK IT!
            let (next_id, slot_kind) = interval.next(env, boundary.clone());
            assert_eq!(outcome_block, &next_id);
            assert_eq!(outcome_slot_kind, &slot_kind);
        }
    }
}