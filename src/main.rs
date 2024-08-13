use blindsort::{
    bench, bench_revolut, bench_revolut_upto,
    blindsort::{bitonic_sort, direct_sort, double_blind_permutation, simple_sort},
};
use revolut::PublicKey;

fn main() {
    // blindsort::cache::write_keys_to_file();

    println!("bench revolut sorts");
    println!("name\t4 values\t8 values\t16 values\t32 values");
    bench_revolut("2bp", PublicKey::blind_sort_2bp);
    bench_revolut("bcs", PublicKey::blind_counting_sort);
    bench_revolut("bma", PublicKey::blind_sort_bma);

    println!("bench tfhe sorts");
    println!("name\t4 values\t8 values\t16 values\t32 values");
    bench("bitonic", bitonic_sort);
    bench("simple", simple_sort);
    bench("direct", direct_sort);
    bench("2bp", double_blind_permutation);
}
