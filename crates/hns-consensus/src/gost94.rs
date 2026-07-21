//! GOST R 34.11-94 with the CryptoPro parameter set used by DNSSEC digest
//! type 3 and HSD's pinned `bns`/`bcrypto` dependency.

const BLOCK_SIZE: usize = 32;

const C: [u8; BLOCK_SIZE] = [
    0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
    0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff,
];

const S_CRYPTOPRO: [[u8; 16]; 8] = [
    [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
    [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
    [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
    [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
    [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
    [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
    [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
    [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12],
];

/// Hash a complete byte slice using the exact one-shot semantics used by
/// `bcrypto/lib/gost94` for DNSSEC DS records.
pub(crate) fn digest(data: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut state = [0u8; BLOCK_SIZE];
    let mut sigma = [0u8; BLOCK_SIZE];

    let mut chunks = data.chunks_exact(BLOCK_SIZE);
    for chunk in &mut chunks {
        let block: &[u8; BLOCK_SIZE] = chunk.try_into().expect("exact GOST94 block");
        compress(&mut state, block);
        add_block(&mut sigma, block);
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut block = [0u8; BLOCK_SIZE];
        block[..remainder.len()].copy_from_slice(remainder);
        compress(&mut state, &block);
        add_block(&mut sigma, &block);
    }

    let bit_length = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut length_block = [0u8; BLOCK_SIZE];
    length_block[..8].copy_from_slice(&bit_length.to_le_bytes());
    compress(&mut state, &length_block);
    compress(&mut state, &sigma);
    state
}

fn compress(state: &mut [u8; BLOCK_SIZE], message: &[u8; BLOCK_SIZE]) {
    let mut encrypted = *state;

    let mut u = *state;
    let mut v = *message;
    let mut key = permute(&xor(&u, &v));
    encrypt(&mut encrypted, 0, &key);

    u = transform_a(&u);
    v = transform_a(&transform_a(&v));
    key = permute(&xor(&u, &v));
    encrypt(&mut encrypted, 8, &key);

    u = transform_a(&u);
    xor_in_place(&mut u, &C);
    v = transform_a(&transform_a(&v));
    key = permute(&xor(&u, &v));
    encrypt(&mut encrypted, 16, &key);

    u = transform_a(&u);
    v = transform_a(&transform_a(&v));
    key = permute(&xor(&u, &v));
    encrypt(&mut encrypted, 24, &key);

    for _ in 0..12 {
        psi(&mut encrypted);
    }
    xor_in_place(&mut encrypted, message);
    psi(&mut encrypted);
    xor_in_place(state, &encrypted);
    for _ in 0..61 {
        psi(state);
    }
}

fn encrypt(message: &mut [u8; BLOCK_SIZE], offset: usize, key: &[u8; BLOCK_SIZE]) {
    let mut a = read_u32(message, offset);
    let mut b = read_u32(message, offset + 4);
    let mut words = [0u32; 8];
    for (index, word) in words.iter_mut().enumerate() {
        *word = read_u32(key, index * 4);
    }

    for _ in 0..3 {
        for word in words {
            let next = b ^ round(a, word);
            b = a;
            a = next;
        }
    }
    for word in words.into_iter().rev() {
        let next = b ^ round(a, word);
        b = a;
        a = next;
    }

    message[offset..offset + 4].copy_from_slice(&b.to_le_bytes());
    message[offset + 4..offset + 8].copy_from_slice(&a.to_le_bytes());
}

fn round(value: u32, key: u32) -> u32 {
    substitute(value.wrapping_add(key)).rotate_left(11)
}

fn substitute(value: u32) -> u32 {
    let mut output = 0u32;
    for (index, row) in S_CRYPTOPRO.iter().enumerate() {
        let shift = index * 4;
        let nibble = ((value >> shift) & 0x0f) as usize;
        output |= u32::from(row[nibble]) << shift;
    }
    output
}

fn transform_a(value: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    output[..24].copy_from_slice(&value[8..]);
    for index in 0..8 {
        output[24 + index] = value[index] ^ value[8 + index];
    }
    output
}

fn permute(value: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = [0u8; BLOCK_SIZE];
    for column in 0..4 {
        for row in 0..8 {
            output[column + 4 * row] = value[8 * column + row];
        }
    }
    output
}

fn psi(value: &mut [u8; BLOCK_SIZE]) {
    let original = *value;
    value[..30].copy_from_slice(&original[2..]);
    value[30] = original[0] ^ original[2] ^ original[4] ^ original[6] ^ original[24] ^ original[30];
    value[31] = original[1] ^ original[3] ^ original[5] ^ original[7] ^ original[25] ^ original[31];
}

fn add_block(sum: &mut [u8; BLOCK_SIZE], block: &[u8; BLOCK_SIZE]) {
    let mut carry = 0u16;
    for index in 0..BLOCK_SIZE {
        carry += u16::from(sum[index]) + u16::from(block[index]);
        sum[index] = carry as u8;
        carry >>= 8;
    }
}

fn xor(left: &[u8; BLOCK_SIZE], right: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut output = *left;
    xor_in_place(&mut output, right);
    output
}

fn xor_in_place(left: &mut [u8; BLOCK_SIZE], right: &[u8; BLOCK_SIZE]) {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= right;
    }
}

fn read_u32(value: &[u8; BLOCK_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes(value[offset..offset + 4].try_into().expect("u32 slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let nibble = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid test vector"),
                };
                (nibble(pair[0]) << 4) | nibble(pair[1])
            })
            .collect()
    }

    #[test]
    fn cryptopro_vectors_match_hsds_pinned_bcrypto() {
        let vectors = [
            (
                "",
                "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
            ),
            (
                "61",
                "e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011",
            ),
            (
                "616263",
                "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c",
            ),
            (
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "a6c864c7605ed814f1cc7c732c9c1fc2817461eaa15fd446efb9b8b5d184a9e0",
            ),
            (
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "816119b9a52e0915150f972dcb46e043a7b6707bce56b5c37dd6a8322f502565",
            ),
            (
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "4b8f048ec782f26c08618d970a031b45f78cd54397f1441b1d9be49ef6c97b4b",
            ),
        ];
        for (input, expected) in vectors {
            assert_eq!(digest(&decode_hex(input)).to_vec(), decode_hex(expected));
        }
    }
}
