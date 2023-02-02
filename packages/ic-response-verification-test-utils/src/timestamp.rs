use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_timestamp(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

pub fn get_current_timestamp() -> u128 {
    get_timestamp(SystemTime::now())
}
