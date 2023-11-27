use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    AesGcmSiv, Nonce,
};

use aes::Aes192;
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::Payload;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

pub type Aes192GcmSiv = AesGcmSiv<Aes192>;

struct VectorArgs {
    nonce: String,
    key: String,
    aad: String,
    tag: String,
    plaintext: String,
    ciphertext: String,
}

fn validate(v: &VectorArgs) {
    let key_bytes = hex::decode(&v.key).unwrap();
    let nonce_bytes = hex::decode(&v.nonce).unwrap();
    let aad_bytes = hex::decode(&v.aad).unwrap();
    let plaintext_bytes = hex::decode(&v.plaintext).unwrap();
    let expected_ciphertext_bytes = hex::decode(&v.ciphertext).unwrap();
    let expected_tag_bytes = hex::decode(&v.tag).unwrap();

    let key_array: [u8; 24] = key_bytes.try_into().unwrap();
    let cipher = Aes192GcmSiv::new(&GenericArray::from(key_array));

    let payload = Payload {
        msg: plaintext_bytes.as_slice(),
        aad: aad_bytes.as_slice(),
    };
    let encrypted_bytes = cipher
        .encrypt(Nonce::from_slice(nonce_bytes.as_slice()), payload)
        .unwrap();
    let (ciphertext_bytes, tag_bytes) = encrypted_bytes.split_at(plaintext_bytes.len());
    assert_eq!(ciphertext_bytes, expected_ciphertext_bytes);
    assert_eq!(tag_bytes, expected_tag_bytes);
}

fn validate_vectors(filename: &Path) {
    let file = File::open(filename).expect("Failed to open file");
    let reader = io::BufReader::new(file);

    let mut vector: Option<VectorArgs> = None;

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let segments: Vec<&str> = line.splitn(2, " = ").collect();

        match segments.first() {
            Some(&"COUNT") => {
                if let Some(v) = vector.take() {
                    validate(&v);
                }
                vector = Some(VectorArgs {
                    nonce: String::new(),
                    key: String::new(),
                    aad: String::new(),
                    tag: String::new(),
                    plaintext: String::new(),
                    ciphertext: String::new(),
                });
            }
            Some(&"IV") => {
                if let Some(v) = &mut vector {
                    v.nonce = segments[1].parse().expect("Failed to parse IV");
                }
            }
            Some(&"Key") => {
                if let Some(v) = &mut vector {
                    v.key = segments[1].to_string();
                }
            }
            Some(&"AAD") => {
                if let Some(v) = &mut vector {
                    v.aad = segments[1].to_string();
                }
            }
            Some(&"Tag") => {
                if let Some(v) = &mut vector {
                    v.tag = segments[1].to_string();
                }
            }
            Some(&"Plaintext") => {
                if let Some(v) = &mut vector {
                    v.plaintext = segments[1].to_string();
                }
            }
            Some(&"Ciphertext") => {
                if let Some(v) = &mut vector {
                    v.ciphertext = segments[1].to_string();
                }
            }
            _ => {}
        }
    }

    if let Some(v) = vector {
        validate(&v);
    }
}

fn main() {
    validate_vectors(Path::new(
        "vectors/cryptography_vectors/ciphers/AES/GCM-SIV/aes-192-gcm-siv.txt",
    ));
    println!("AES-192-GCM-SIV OK.")
}
