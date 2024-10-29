use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing},
};

fn bench_addition(c: &mut Criterion) {
    let p_bytes = [
        37, 35, 100, 130, 64, 0, 0, 1, 186, 52, 77, 128, 0, 0, 0, 8, 97, 33, 0, 0, 0, 0, 0, 19,
        167, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let q_bytes = [
        37, 35, 100, 130, 64, 0, 0, 1, 186, 52, 77, 128, 0, 0, 0, 8, 97, 33, 0, 0, 0, 0, 0, 19,
        167, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat();

    c.bench_function("bn128 addition", |b| {
        b.iter(|| alt_bn128_addition(&input_bytes))
    });
}

fn bench_multiplication(c: &mut Criterion) {
    let point_bytes = [
        37, 35, 100, 130, 64, 0, 0, 1, 186, 52, 77, 128, 0, 0, 0, 8, 97, 33, 0, 0, 0, 0, 0, 19,
        167, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let scalar_bytes = [
        1, 1, 1, 1, 64, 0, 0, 1, 186, 52, 77, 128, 0, 0, 0, 8, 97, 33, 0, 0, 0, 0, 0, 19, 167, 0,
        0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    ];

    let input_bytes = [&point_bytes[..], &scalar_bytes[..]].concat();

    c.bench_function("bn128 multiplication", |b| {
        b.iter(|| alt_bn128_multiplication(&input_bytes))
    });
}

fn bench_pairing(c: &mut Criterion) {
    let p_bytes = [
        37, 35, 100, 130, 64, 0, 0, 1, 186, 52, 77, 128, 0, 0, 0, 8, 97, 33, 0, 0, 0, 0, 0, 19,
        167, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];
    let q_bytes = [
        25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73, 51,
        53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194, 24, 0, 222, 239, 18, 31, 30, 118,
        66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70, 222, 189, 92,
        217, 146, 246, 237,
    ];

    let input_bytes = [&p_bytes[..], &q_bytes[..]].concat();

    c.bench_function("bn128 pairing", |b| {
        b.iter(|| alt_bn128_pairing(&input_bytes))
    });
}

criterion_group!(benches, bench_addition, bench_multiplication, bench_pairing,);
criterion_main!(benches);
