//! Consensus script hashes that are intentionally implemented without a new
//! dependency surface. These routines are small, deterministic, allocation-
//! bounded reference implementations used only by script opcodes.

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];

    for block in pad_big_endian(data).chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte chunk"));
        }
        for index in 16..80 {
            words[index] = (words[index - 3]
                ^ words[index - 8]
                ^ words[index - 14]
                ^ words[index - 16])
                .rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.into_iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut output = [0u8; 20];
    for (chunk, word) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
        0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786,
        0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147,
        0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a,
        0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];

    let mut state = [
        0x6a09_e667u32,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    for block in pad_big_endian(data).chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte chunk"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = sigma0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (word, addition) in state
            .iter_mut()
            .zip([a, b, c, d, e, f, g, h])
        {
            *word = word.wrapping_add(addition);
        }
    }

    let mut output = [0u8; 32];
    for (chunk, word) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
}

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    const RL: [usize; 80] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6,
        15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6,
        13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];
    const RR: [usize; 80] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13,
        5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12,
        2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];
    const SL: [u32; 80] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11,
        9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14,
        8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6,
        5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ];
    const SR: [u32; 80] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12,
        8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13,
        5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5,
        15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ];

    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];

    for block in pad_little_endian(data).chunks_exact(64) {
        let mut words = [0u32; 16];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_le_bytes(chunk.try_into().expect("four-byte chunk"));
        }

        let [mut al, mut bl, mut cl, mut dl, mut el] = state;
        let [mut ar, mut br, mut cr, mut dr, mut er] = state;

        for index in 0..80 {
            let left = al
                .wrapping_add(ripemd_function(index, bl, cl, dl))
                .wrapping_add(words[RL[index]])
                .wrapping_add(ripemd_left_constant(index))
                .rotate_left(SL[index])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = left;

            let right_round = 79 - index;
            let right = ar
                .wrapping_add(ripemd_function(right_round, br, cr, dr))
                .wrapping_add(words[RR[index]])
                .wrapping_add(ripemd_right_constant(index))
                .rotate_left(SR[index])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = right;
        }

        let next = state[1].wrapping_add(cl).wrapping_add(dr);
        state[1] = state[2].wrapping_add(dl).wrapping_add(er);
        state[2] = state[3].wrapping_add(el).wrapping_add(ar);
        state[3] = state[4].wrapping_add(al).wrapping_add(br);
        state[4] = state[0].wrapping_add(bl).wrapping_add(cr);
        state[0] = next;
    }

    let mut output = [0u8; 20];
    for (chunk, word) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    output
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

pub fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

fn ripemd_function(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | ((!x) & z),
        32..=47 => (x | (!y)) ^ z,
        48..=63 => (x & z) | (y & (!z)),
        _ => x ^ (y | (!z)),
    }
}

fn ripemd_left_constant(round: usize) -> u32 {
    match round {
        0..=15 => 0x0000_0000,
        16..=31 => 0x5a82_7999,
        32..=47 => 0x6ed9_eba1,
        48..=63 => 0x8f1b_bcdc,
        _ => 0xa953_fd4e,
    }
}

fn ripemd_right_constant(round: usize) -> u32 {
    match round {
        0..=15 => 0x50a2_8be6,
        16..=31 => 0x5c4d_d124,
        32..=47 => 0x6d70_3ef3,
        48..=63 => 0x7a6d_76e9,
        _ => 0x0000_0000,
    }
}

fn pad_big_endian(data: &[u8]) -> Vec<u8> {
    pad(data, true)
}

fn pad_little_endian(data: &[u8]) -> Vec<u8> {
    pad(data, false)
}

fn pad(data: &[u8], big_endian_length: bool) -> Vec<u8> {
    let mut padded = Vec::with_capacity(data.len().saturating_add(72));
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_length = (data.len() as u64).wrapping_mul(8);
    if big_endian_length {
        padded.extend_from_slice(&bit_length.to_be_bytes());
    } else {
        padded.extend_from_slice(&bit_length.to_le_bytes());
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0u8; N];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            output[index] = u8::from_str_radix(
                std::str::from_utf8(pair).expect("hex utf8"),
                16,
            )
            .expect("hex byte");
        }
        output
    }

    #[test]
    fn standard_hash_vectors_match() {
        assert_eq!(
            sha1(b"abc"),
            hex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            sha256(b"abc"),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            ripemd160(b"abc"),
            hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        );
        assert_eq!(
            hash160(b"abc"),
            hex("bb1be98c142444d7a56aa3981c3942a978e4dc33")
        );
        assert_eq!(
            hash256(b"abc"),
            hex("4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
        );
    }
}
