#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssb_legacy_msg;
extern crate ssb_legacy_msg_data;

use ssb_legacy_msg::{Message, json::{from_legacy, to_legacy_vec}};
use ssb_legacy_msg_data::value::Value;

fuzz_target!(|data: &[u8]| {
    // This comment keeps rustfmt from breaking the fuzz macro...
    match from_legacy::<Value>(data) {
        Ok((msg, _)) => {
            let sign_json = to_legacy_vec(&msg, false);
            let redecoded = from_legacy::<Value>(&sign_json[..]).unwrap().0;
            assert_eq!(msg, redecoded);
        }

        Err(_) => {}
    }
});
