extern crate ssb_legacy_msg_data;
extern crate ssb_legacy_msg;

use std::fs::File;
use std::io::prelude::*;

use ssb_legacy_msg::{Message, json, verify, clmr::to_clmr_vec};
use ssb_legacy_msg_data::value::ContentValue;

fn main() -> std::io::Result<()> {
    let mut file = File::open("examples/log_aljoscha")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let messages = contents.split("\n\n");

    let mut prev_hash = None;
    let mut prev_seq = 0;

    let mut signing_size = 0;
    let mut json_compact_size = 0;
    let mut clmr_size = 0;

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

                signing_size += sig_enc.as_bytes().len();
            }

            Err(e) => {
                println!("{:#?}", msg);
                panic!("{:?}", e);
            }
        }

        match json::to_legacy_string(&msg, true) {
            Ok(json_compact_enc) => {
                json_compact_size += json_compact_enc.as_bytes().len();
            }

            Err(e) => {
                println!("{:#?}", msg);
                panic!("{:?}", e);
            }
        }

        match to_clmr_vec(&msg) {
            Ok(clmr) => {
                clmr_size += clmr.len();
            }

            Err(e) => {
                println!("{:#?}", msg);
                panic!("{:?}", e);
            }
        }
    }

    println!("signing: {:?}", signing_size);
    println!("compact json: {:?}", json_compact_size);
    println!("clmr {:?}", clmr_size);

    Ok(())
}
