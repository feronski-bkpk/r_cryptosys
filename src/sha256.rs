pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut m = message.to_vec();
    m.push(0x80);
    if 64 - m.len() % 64 < 8 {
        m.append(&mut vec![0u8; 64 - m.len() % 64])
    }
    m.append(&mut vec![0u8; 64 - m.len() % 64 - 8]);
    m.append(&mut (message.len() as u64 * 8).to_be_bytes().to_vec());
    let blocks = m.chunks_exact(64);

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    for block in blocks {
        let mut w: Vec<u32> = block.chunks_exact(4).map(|chunk| {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        }).collect();
        w.append(&mut vec![0u32; 48]);

        for i in 16..64 {
            let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
            let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut tmp_h: [u32; 8] = h.clone();

        for i in 0..64 {
            let s1 = (tmp_h[4].rotate_right(6)) ^ (tmp_h[4].rotate_right(11)) ^ (tmp_h[4].rotate_right(25));
            let ch = (tmp_h[4] & tmp_h[5]) ^ (!tmp_h[4] & tmp_h[6]);
            let temp1 = tmp_h[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = (tmp_h[0].rotate_right(2)) ^ (tmp_h[0].rotate_right(13)) ^ (tmp_h[0].rotate_right(22));
            let maj = (tmp_h[0] & tmp_h[1]) ^ (tmp_h[0] & tmp_h[2]) ^ (tmp_h[1] & tmp_h[2]);
            let temp2 = s0.wrapping_add(maj);


            tmp_h[7] = tmp_h[6];
            tmp_h[6] = tmp_h[5];
            tmp_h[5] = tmp_h[4];
            tmp_h[4] = tmp_h[3].wrapping_add(temp1);
            tmp_h[3] = tmp_h[2];
            tmp_h[2] = tmp_h[1];
            tmp_h[1] = tmp_h[0];
            tmp_h[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            h[i] = h[i].wrapping_add(tmp_h[i]);
        }
    }

    let mut result = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        result[i*4..(i+1)*4].copy_from_slice(&word.to_be_bytes());
    }
    result
}