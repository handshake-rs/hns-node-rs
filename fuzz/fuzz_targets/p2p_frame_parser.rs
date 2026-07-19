#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let command_len = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
    let _ = data.split_at(command_len);
});
