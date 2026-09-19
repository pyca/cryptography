//! Release measurement of repeated public-key import and verification.
//! Cargo run --release --example dsa_reimport -- <threads> <iterations/thread>.
use openssl_bridge::{
    dsa::{Components, ParameterMaterial, PublicKey},
    hash::{self, Algorithm},
};
use std::{
    hint::black_box,
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};
#[derive(Clone)]
struct Vector {
    name: String,
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
    y: Vec<u8>,
    digest: Vec<u8>,
    signature: Vec<u8>,
}
fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return vec![];
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let threads: usize = args.get(1).map_or(1, |v| v.parse().unwrap());
    let iterations: usize = args.get(2).map_or(12, |v| v.parse().unwrap());
    assert!(threads > 0 && iterations > 0);
    let md = Algorithm::from_name("sha256").unwrap();
    let vectors: Vec<_> = include_str!("../tests/vectors/dsa-reimport.txt")
        .lines()
        .map(|line| {
            let f: Vec<_> = line.split_whitespace().collect();
            Vector {
                name: f[0].to_string(),
                p: hex(f[1]),
                q: hex(f[2]),
                g: hex(f[3]),
                y: hex(f[4]),
                digest: hash::digest(md, &hex(f[5])).unwrap(),
                signature: hex(f[6]),
            }
        })
        .collect();
    for vector in vectors {
        let barrier = Arc::new(Barrier::new(threads + 1));
        let mut handles = vec![];
        for _ in 0..threads {
            let v = vector.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let mut parameters = Duration::ZERO;
                let mut verify = Duration::ZERO;
                barrier.wait();
                for _ in 0..iterations {
                    let start = Instant::now();
                    let material = ParameterMaterial::from_components(Components {
                        p: &v.p,
                        q: &v.q,
                        g: &v.g,
                    })
                    .unwrap();
                    let params = material.validate().unwrap();
                    parameters += start.elapsed();
                    let start = Instant::now();
                    let key = PublicKey::from_components(params, &v.y).unwrap();
                    assert!(black_box(
                        key.verify_digest(md, &v.digest, &v.signature).unwrap()
                    ));
                    verify += start.elapsed();
                }
                (parameters, verify)
            }));
        }
        let start = Instant::now();
        barrier.wait();
        let (mut parameters, mut verify) = (Duration::ZERO, Duration::ZERO);
        for h in handles {
            let (p, v) = h.join().unwrap();
            parameters += p;
            verify += v;
        }
        println!("{} threads={} operations={} elapsed_ns={} parameter_thread_ns={} key_and_verify_thread_ns={}", vector.name, threads, threads * iterations, start.elapsed().as_nanos(), parameters.as_nanos(), verify.as_nanos());
    }
}
