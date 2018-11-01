#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssb_legacy_msg;
extern crate ssb_legacy_msg_data;

use ssb_legacy_msg::{Message, clmr::{from_clmr, to_clmr_vec}};
use ssb_legacy_msg_data::value::ContentValue;

fuzz_target!(|data: &[u8]| {
    // This comment keeps rustfmt from breaking the fuzz macro...
    match from_clmr::<ContentValue>(data) {
        Ok((msg, _)) => {
            let enc = to_clmr_vec(&msg).unwrap();
            let redecoded = from_clmr::<ContentValue>(&enc[..]).unwrap().0;
            assert_eq!(msg, redecoded);
        }

        Err(_) => {}
    }
});
