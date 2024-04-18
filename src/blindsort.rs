use tfhe::{
    core_crypto::commons::traits::CastFrom,
    prelude::{FheEq, FheOrd, FheTrivialEncrypt},
};

use crate::{timeit, Cipher, Plain};

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
    // permutation values outside the 0..data.len() range will be ignored
    assert_eq!(data.len(), permutation.len());
    (0..data.len())
        .map(|i| {
            (0..data.len())
                .map(|j| {
                    let jtoi = permutation[j].eq(i as Plain);
                    Cipher::cast_from(jtoi) * &data[j]
                })
                .sum::<Cipher>()
        })
        .collect()
}

/// direct sorting algorithm
pub fn blind_sort(data: &[Cipher]) -> Vec<Cipher> {
    let permutation = sorting_permutation(&data);
    timeit("blind permutation", || {
        apply_permutation(&data, &permutation)
    })
}

pub fn blind_sort_2bp(data: &[Cipher]) -> Vec<Cipher> {
    let partially = apply_permutation(&data, &data);
    let mut cnt = Cipher::encrypt_trivial(Plain::from(0));
    let permutation = Vec::from_iter(partially.iter().map(|x| {
        let z = x.eq(0);
        cnt += Cipher::cast_from(z);
        x - &cnt
    }));
    apply_permutation(&partially, &permutation)
}

#[cfg(test)]
mod tests {
    use crate::{
        blindsort::{blind_sort, blind_sort_2bp},
        cache::read_keys_from_file,
        decrypt_array, encrypt_array, timeit,
    };
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
    fn test_blind_sort_ds() {
        let (client_key, server_key) = read_keys_from_file();
        set_server_key(server_key);
        // let data = [1, 3, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let data = Vec::from_iter(0..32);
        let encrypted = encrypt_array(&data, &client_key);

        let sorted = timeit("blind_sort", || blind_sort(&encrypted));

        let decrypted = decrypt_array(&sorted, &client_key);
        let mut data = data;
        data.sort();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_blind_sort_2bp() {
        let (client_key, server_key) = read_keys_from_file();
        set_server_key(server_key);
        // let data = [1, 3, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let data = Vec::from_iter(0..32);
        let encrypted = encrypt_array(&data, &client_key);

        let sorted = timeit("blind_sort", || blind_sort_2bp(&encrypted));

        let decrypted = decrypt_array(&sorted, &client_key);
        let mut data = data;
        data.sort();
        data.rotate_left(1);
        assert_eq!(decrypted, data);
    }
}
