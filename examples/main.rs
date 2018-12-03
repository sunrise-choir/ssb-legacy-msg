extern crate ssb_legacy_msg_data;
extern crate ssb_legacy_msg;

use std::fs::File;
use std::io::{self, prelude::*};

use ssb_legacy_msg::{Message, json, verify, clmr};
use ssb_legacy_msg_data::value::ContentValue;

// Read the example feed, return the parsed messages, the signing encodings, the compact json encodings, and the clmr encodings.
fn get_data
    ()
    -> Result<(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>), io::Error>
{
    let mut file = File::open("examples/log_aljoscha")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let messages = contents.split("\n\n");

    let mut msgs = Vec::new();
    let mut signing_json_encs = Vec::new();
    let mut compact_json_encs = Vec::new();
    let mut clmr_encs = Vec::new();

    for msg_str in messages {
        let msg = json::from_legacy::<ContentValue>(msg_str.as_bytes())
            .unwrap()
            .0;

        signing_json_encs.push(json::to_legacy_vec(&msg, false).unwrap());
        compact_json_encs.push(json::to_legacy_vec(&msg, true).unwrap());
        clmr_encs.push(clmr::to_clmr_vec(&msg).unwrap());

        msgs.push(msg);
    }

    Ok((msgs, signing_json_encs, compact_json_encs, clmr_encs))
}

fn main() -> std::io::Result<()> {
    let (msgs, sign_jsons, compact_jsons, clmrs) = get_data()?;

    for i in 0..msgs.len() {
        match clmr::from_clmr::<ContentValue>(&clmrs[i]) {
            Ok(..) => {}
            Err(e) => {
                println!("{:?}\n", sign_jsons[i]);
                println!("{:#?}\n", msgs[i]);
                println!("{:x?}\n", clmrs[i]);
                println!("{:?}", e);
            }
        }
        let dec = clmr::from_clmr::<ContentValue>(&clmrs[i]).unwrap().0;
        assert_eq!(dec, msgs[i]);
    }

    Ok(())
}
