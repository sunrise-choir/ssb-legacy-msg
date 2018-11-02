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
  //   // let json_enc = vec![123, 10, 32, 32, 34, 112, 114, 101, 118, 105, 111, 117, 115, 34, 58, 32, 110, 117, 108, 108, 44, 10, 32, 32, 34, 97, 117, 116, 104, 111, 114, 34, 58, 32, 34, 64, 122, 117, 114, 70, 56, 88, 54, 56, 65, 114, 102, 82, 77, 55, 49, 100, 70, 51, 109, 75, 104, 51, 54, 87, 48, 120, 68, 77, 56, 81, 109, 79, 110, 65, 83, 53, 98, 89, 79, 113, 56, 104, 65, 61, 46, 101, 100, 50, 53, 53, 49, 57, 34, 44, 10, 32, 32, 34, 115, 101, 113, 117, 101, 110, 99, 101, 34, 58, 32, 49, 44, 10, 32, 32, 34, 116, 105, 109, 101, 115, 116, 97, 109, 112, 34, 58, 32, 49, 52, 57, 48, 52, 54, 55, 48, 57, 51, 48, 50, 56, 44, 10, 32, 32, 34, 104, 97, 115, 104, 34, 58, 32, 34, 115, 104, 97, 50, 53, 54, 34, 44, 10, 32, 32, 34, 99, 111, 110, 116, 101, 110, 116, 34, 58, 32, 123, 10, 32, 32, 32, 32, 34, 116, 121, 112, 101, 34, 58, 32, 34, 97, 98, 111, 117, 116, 34, 44, 10, 32, 32, 32, 32, 34, 97, 98, 111, 117, 116, 34, 58, 32, 34, 64, 122, 117, 114, 70, 56, 88, 54, 56, 65, 114, 102, 82, 77, 55, 49, 100, 70, 51, 109, 75, 104, 51, 54, 87, 48, 120, 68, 77, 56, 81, 109, 79, 110, 65, 83, 53, 98, 89, 79, 113, 56, 104, 65, 61, 46, 101, 100, 50, 53, 53, 49, 57, 34, 44, 10, 32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 65, 108, 106, 111, 115, 99, 104, 97, 34, 10, 32, 32, 125, 44, 10, 32, 32, 34, 115, 105, 103, 110, 97, 116, 117, 114, 101, 34, 58, 32, 34, 79, 47, 65, 113, 86, 43, 69, 111, 71, 112, 97, 54, 65, 90, 104, 80, 84, 56, 70, 101, 43, 110, 103, 77, 108, 114, 74, 74, 69, 110, 71, 82, 54, 75, 56, 109, 52, 112, 121, 50, 103, 66, 77, 74, 66, 107, 111, 85, 89, 118, 106, 98, 82, 120, 87, 103, 80, 118, 90, 73, 111, 122, 120, 117, 115, 82, 57, 110, 97, 51, 89, 113, 80, 104, 111, 82, 67, 116, 73, 103, 88, 76, 89, 112, 66, 81, 61, 61, 46, 115, 105, 103, 46, 101, 100, 50, 53, 53, 49, 57, 34, 10, 125];
  //   let json_enc = r####"{
  //     "previous": "%0/GcUivL34PR6Wy43sue2+tu7RhiKKEVTKNSEN/+liA=.sha256",
  //     "author": "@zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519",
  //     "sequence": 18,
  //     "timestamp": 1490532586946,
  //     "hash": "sha256",
  //     "content": {
  //       "type": "post",
  //       "text": "thought about self-organizing messages as well, although the ideas I'm presenting here use a more explicit approach. I am new to the scuttleverse and its concepts, so there might be some obvious flaws in my thoughts. Anyways, here we go:\n\nNearly everythikk",
  //       "mentions": []
  //     },
  //     "signature": "cVc7xcxSEweTqLU/aZjgvc5VbahViLOZV9Tynbke6Bvh15zj82WKEPjHiNKkq6JsJQ9hLckq2Lqr1sM10EhSBQ==.sig.ed25519"
  // }"####.as_bytes();
  //   let msg = json::from_legacy::<ContentValue>(&json_enc)
  //       .unwrap()
  //       .0;
  //
  //   let clmr_enc = clmr::to_clmr_vec(&msg).unwrap();
  //   let redec = clmr::from_clmr::<ContentValue>(&clmr_enc).unwrap().0;
  //   // println!("{:?}", msg);
  //
  //   Ok(())

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

    // let mut file = File::open("examples/log_aljoscha")?;
    // let mut contents = String::new();
    // file.read_to_string(&mut contents)?;
    //
    // let messages = contents.split("\n\n");
    //
    // let mut prev_hash = None;
    // let mut prev_seq = 0;
    //
    // let mut signing_size = 0;
    // let mut json_compact_size = 0;
    // let mut clmr_size = 0;
    //
    // for msg_str in messages {
    //     let msg = json::from_legacy::<ContentValue>(msg_str.as_bytes())
    //         .unwrap()
    //         .0;
    //
    //     match json::to_legacy_string(&msg, false) {
    //         Ok(sig_enc) => {
    //             let (hash, len) = verify::hash_and_length(&sig_enc);
    //
    //             assert!(verify::check_length(len));
    //             assert!(verify::check_previous(&msg, &prev_hash));
    //             assert!(verify::check_sequence(&msg, prev_seq));
    //             assert!(verify::check_signature(&sig_enc, &msg.author, &msg.signature));
    //
    //             prev_hash = Some(hash);
    //             prev_seq = msg.sequence;
    //
    //             signing_size += sig_enc.as_bytes().len();
    //         }
    //
    //         Err(e) => {
    //             println!("{:#?}", msg);
    //             panic!("{:?}", e);
    //         }
    //     }
    //
    //     match json::to_legacy_string(&msg, true) {
    //         Ok(json_compact_enc) => {
    //             json_compact_size += json_compact_enc.as_bytes().len();
    //         }
    //
    //         Err(e) => {
    //             println!("{:#?}", msg);
    //             panic!("{:?}", e);
    //         }
    //     }
    //
    //     match to_clmr_vec(&msg) {
    //         Ok(clmr) => {
    //             clmr_size += clmr.len();
    //         }
    //
    //         Err(e) => {
    //             println!("{:#?}", msg);
    //             panic!("{:?}", e);
    //         }
    //     }
    // }
    //
    // println!("signing: {:?}", signing_size);
    // println!("compact json: {:?}", json_compact_size);
    // println!("clmr {:?}", clmr_size);
    //
    // Ok(())
}
