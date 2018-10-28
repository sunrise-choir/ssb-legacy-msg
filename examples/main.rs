extern crate ssb_legacy_msg_data;
extern crate ssb_legacy_msg;

use std::fs::File;
use std::io::prelude::*;

use ssb_legacy_msg::{Message, json, verify};
use ssb_legacy_msg_data::value::ContentValue;

fn main() -> std::io::Result<()> {
    let mut file = File::open("log_aljoscha")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let messages = contents.split("\n\n");

    let mut prev_hash = None;
    let mut prev_seq = 0;

    for msg_str in messages {
        let msg = json::from_legacy::<ContentValue>(msg_str.as_bytes())
            .unwrap()
            .0;

        match json::to_legacy_string(&msg, false) {
            Ok(sig_enc) => {
                let (hash, len) = verify::hash_and_length(&sig_enc);

                assert!(verify::check_length(len));
                assert!(verify::check_previous(&msg, &prev_hash));
                assert!(verify::check_sequence(&msg, prev_seq));
                assert!(verify::check_signature(&sig_enc, &msg.author, &msg.signature));

                prev_hash = Some(hash);
                prev_seq = msg.sequence;
            }

            Err(e) => {
                println!("{:#?}", msg);
                panic!("{:?}", e);
            }
        }

        // let sig_enc = json::to_legacy_string(&msg, false).unwrap();
        // let (hash, len) = verify::hash_and_length(&sig_enc);
        //
        // assert!(verify::check_length(len));
        // assert!(verify::check_previous(&msg, &prev_hash));
        // assert!(verify::check_sequence(&msg, prev_seq));
        //
        // prev_hash = Some(hash);
        // prev_seq = msg.sequence;





        // println!("{}\n----------------------\n\n", msg_str);
        // let foo =
        //     ssb_legacy_msg_data::json::from_slice_partial::<ssb_legacy_msg_data::value::Value>(msg_str.as_bytes())
        //         .unwrap();
        // match foo {
        //     (ssb_legacy_msg_data::value::Value::Object(ref map), _) => {
        //         let bar = map.get("value").unwrap();
        //         let real_msg_str = ssb_legacy_msg_data::json::to_vec(bar, false).unwrap();
        //
        //         match json::from_legacy::<ContentValue>(&real_msg_str) {
        //             Ok(msg) => {
        //                 // noop
        //             }
        //
        //             Err(err) => {
        //                 println!("{}", std::str::from_utf8(&real_msg_str).unwrap());
        //                 println!("{:?}", err);
        //             }
        //         }
        //
        //         let msg = json::from_legacy::<ContentValue>(&real_msg_str).unwrap();
        //
        //
        //     }
        //     _ => panic!("Oh no!"),
        // }
    }

    Ok(())
}
