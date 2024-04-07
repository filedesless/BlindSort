use tfhe::{
    core_crypto::commons::traits::CastFrom,
    prelude::{FheEq, FheOrd, FheTrivialEncrypt},
};

use crate::{Cipher, Plain};

/// computes the sorting permutation of a given array of ciphertexts
fn sorting_permutation(data: &[Cipher]) -> Vec<Cipher> {
    let mut out = vec![Cipher::encrypt_trivial(Plain::from(0)); data.len()];
    for i in 0..data.len() {
        for j in 0..i {
            let z = data[i].gt(&data[j]);
            let nz = !&z;
            out[i] += Cipher::cast_from(z);
            out[j] += Cipher::cast_from(nz);
        }
    }
    out
}

/// re-order given array of ciphertexts based on ciphered indices
fn apply_permutation(data: &[Cipher], permutation: &[Cipher]) -> Vec<Cipher> {
    let mut out = vec![Cipher::encrypt_trivial(Plain::from(0)); data.len()];
    for i in 0..data.len() {
        for j in 0..data.len() {
            let z = permutation[j].eq(i as u8);
            out[i] += Cipher::cast_from(z) * &data[j];
        }
    }
    out
}

/// direct sorting algorithm
pub fn blind_sort(data: &[Cipher]) -> Vec<Cipher> {
    let permutation = sorting_permutation(&data);
    apply_permutation(&data, &permutation)
}

#[cfg(test)]
mod tests {
    use crate::{blindsort::blind_sort, cache::read_keys_from_file, decrypt_array, encrypt_array};
    use tfhe::set_server_key;

    use super::sorting_permutation;

    #[test]
    fn test_sorting_permutation() {
        let (client_key, server_key) = read_keys_from_file();
        set_server_key(server_key);
        let data = [5, 7, 3, 2];
        let encrypted = encrypt_array(&data, &client_key);

        let permutation = sorting_permutation(&encrypted);

        let decrypted = decrypt_array(&permutation, &client_key);
        assert_eq!(decrypted, [2, 3, 1, 0]);
    }

    #[test]
    fn test_blind_sort() {
        let (client_key, server_key) = read_keys_from_file();
        set_server_key(server_key);
        let data = [5, 7, 3, 2];
        let encrypted = encrypt_array(&data, &client_key);

        let sorted = blind_sort(&encrypted);

        let decrypted = decrypt_array(&sorted, &client_key);
        let mut data = data;
        data.sort();
        assert_eq!(decrypted, data);
    }
}
