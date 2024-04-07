pub mod blindsort;
pub mod cache;

use std::time::Instant;

use tfhe::{prelude::{FheDecrypt, FheEncrypt}, ClientKey, FheUint8};

pub type Plain = u8;
pub type Cipher = FheUint8;

pub fn timeit<F: Fn() -> T, T>(name: &str, f: F) -> T {
    let begin = Instant::now();
    let result = f();
    let elapsed = Instant::now() - begin;
    println!("{}: {:?}", name, elapsed);
    result
}

pub fn encrypt_array(data: &[Plain], client_key: &ClientKey) -> Vec<Cipher> {
    data.iter().map(|&c| Cipher::encrypt(c, client_key)).collect()
}

pub fn decrypt_array(data: &[Cipher], client_key: &ClientKey) -> Vec<Plain> {
    data.iter().map(|c| c.decrypt(&client_key)).collect()
}