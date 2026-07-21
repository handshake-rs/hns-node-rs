#![no_main]

use hns_p2p::{decode_frame, NetworkMagic};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for magic in [
        NetworkMagic::Mainnet,
        NetworkMagic::Testnet,
        NetworkMagic::Regtest,
        NetworkMagic::Simnet,
    ] {
        if let Ok(frame) = decode_frame(magic, data) {
            let _ = frame.decode_packet();
        }
    }
});
