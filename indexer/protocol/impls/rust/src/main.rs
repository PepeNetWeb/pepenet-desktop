//! PepeNet namespace reference state machine (clean-room Rust, zero external crates).
//!
//! Modes:
//!   sm selftest                  — crypto KATs + decoder round-trips + fold vector battery + attrib KATs
//!   sm digest                    — dump a small deterministic scenario's state_digest
//!   sm random <seed> <count>     — own soak generator (NOT reference-comparable; see SPEC-RATIONALE.md)
//!   sm attrib-demo               — run a couple of attribution byte-logic demonstrations

mod attrib;
mod attrib_curve;
mod decode;
mod digest;
mod ecmh;
mod encode;
mod fold;
mod forkvectors;
mod generator;
mod model;
mod modes;
mod oracle;
mod prng;
mod ripemd160;
mod scenario;
mod secp256k1;
mod selftest;
mod sha256;
mod types;

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("selftest");
    match mode {
        "selftest" => {
            let ok = selftest::run();
            if !ok {
                exit(1);
            }
        }
        "digest" => {
            let (id, sd) = generator::run_random(1, 64);
            println!("input_digest={}", id);
            println!("state_digest={}", sd);
            println!("# NOTE: this impl's OWN golden — NOT comparable to the forbidden reference.");
        }
        "random" => {
            let seed = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1u64);
            let count = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100u64);
            let (id, sd) = generator::run_random(seed, count);
            println!("input_digest={}", id);
            println!("state_digest={}", sd);
        }
        "properties" | "meta" | "reorg" | "reorgfuzz" | "fuzz" => {
            let seed = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1u64);
            let count = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100u64);
            match mode {
                "properties" => modes::properties(seed, count),
                "meta" => modes::meta(seed, count),
                "reorg" => modes::reorg(seed, count),
                "reorgfuzz" => modes::reorgfuzz(seed, count),
                "fuzz" => modes::fuzz(seed, count),
                _ => unreachable!(),
            }
        }
        "attrib-demo" => attrib_demo(),
        "scenario" => exit(scenario::run()),
        "attrib-curve" => exit(attrib_curve::run()),
        "ecmh" => exit(ecmh::run()),
        "forkvectors" => exit(forkvectors::run()),
        other => {
            eprintln!("unknown mode: {}", other);
            eprintln!(
                "modes: selftest | digest | random <seed> <count> | scenario | attrib-demo | attrib-curve | \
                 ecmh | forkvectors | \
                 properties <seed> <count> | meta <seed> <count> | reorg <seed> <count> | \
                 reorgfuzz <seed> <count> | fuzz <seed> <count>"
            );
            exit(2);
        }
    }
}

fn attrib_demo() {
    // Demonstrate the §4 byte-logic over a couple of hand-built raw txs is left to selftest;
    // here we just confirm the oracle/primitives are wired.
    use attrib::*;
    let pk = [0x02u8; 33];
    println!("on_curve(demo pk) = {}", on_curve(&pk));
    let h = [1u8; 32];
    let r = [2u8; 32];
    let s = [3u8; 32];
    println!("verify(demo) = {}", verify(&h, &r, &s, &pk));
    println!("(full attribution vectors run under `selftest`)");
}
