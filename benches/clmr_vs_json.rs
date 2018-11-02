#[macro_use]
extern crate criterion;

use std::fs::File;
use std::io::{self, prelude::*};

use criterion::{Criterion, Fun};

use ssb_legacy_msg::{Message, json, clmr};
use ssb_legacy_msg_data::value::ContentValue;

// Read the example feed, return the parsed messages, the signing encodings, the compact json encodings, and the clmr encodings.
fn get_data() -> Result<(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>), io::Error> {
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

fn do_deserialize_signing_json(encs: &(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>)) {
    for enc in encs.1.iter() {
        json::from_legacy::<ContentValue>(&enc).unwrap();
    }
}

fn do_deserialize_compact_json(encs: &(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>)) {
    for enc in encs.2.iter() {
        json::from_legacy::<ContentValue>(&enc).unwrap();
    }
}

fn do_deserialize_clmr(encs: &(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>)) {
    for enc in encs.3.iter() {
        clmr::from_clmr::<ContentValue>(&enc).unwrap();
    }
}

fn bench_deserialization(c: &mut Criterion) {
    let deserialize_signing_json = Fun::new("deserialize signing json", |b, data| b.iter(|| do_deserialize_signing_json(data)));
    let deserialize_compact_json = Fun::new("deserialize compact json", |b, data| b.iter(|| do_deserialize_compact_json(data)));
    let deserialize_clmr = Fun::new("deserialize clmr", |b, data| b.iter(|| do_deserialize_clmr(data)));

    let data = get_data().unwrap();
    let functions = vec!(deserialize_signing_json, deserialize_compact_json, deserialize_clmr);
    c.bench_functions("deserialize each message", functions, data);
}

fn do_serialize_signing_json(encs: &(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>)) {
    let mut w = io::sink();
    for msg in encs.0.iter() {
        json::to_legacy(&msg, &mut w, false).unwrap();
    }
}

fn do_serialize_compact_json(encs: &(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>)) {
    let mut w = io::sink();
    for msg in encs.0.iter() {
        json::to_legacy(&msg, &mut w, true).unwrap();
    }
}

fn do_serialize_clmr(encs: &(Vec<Message<ContentValue>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>)) {
    let mut w = io::sink();
    for msg in encs.0.iter() {
        clmr::to_clmr(&msg, &mut w).unwrap();
    }
}

fn bench_serialization(c: &mut Criterion) {
    let serialize_signing_json = Fun::new("serialize signing json", |b, data| b.iter(|| do_serialize_signing_json(data)));
    let serialize_compact_json = Fun::new("serialize compact json", |b, data| b.iter(|| do_serialize_compact_json(data)));
    let serialize_clmr = Fun::new("serialize clmr", |b, data| b.iter(|| do_serialize_clmr(data)));

    let data = get_data().unwrap();
    let functions = vec!(serialize_signing_json, serialize_compact_json, serialize_clmr);
    c.bench_functions("serialize each message", functions, data);
}

criterion_group!(benches, bench_deserialization, bench_serialization);
criterion_main!(benches);
