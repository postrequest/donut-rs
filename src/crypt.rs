#![allow(unused_assignments)]

use crate::definitions::*;
use crate::utils::*;

#[allow(unused)]
pub fn encrypt(master_key: [u8; 16], ctr: [u8; 16], data: Vec<u8>) -> Vec<u8> {
    let mut ctr = ctr;
    let mut length = data.len() as u32;
    let mut x_u8 = [0u8; 16];
    let mut x = [0u32; 4];
    let mut r = 0u32;
    let mut p: usize = 0;
    let mut encrypted = data;
    let key = to_u32x4(&master_key);
    while length > 0 {
        // copy counter and nonce to local buffer
        x_u8 = ctr;
        x = to_u32x4(&x_u8);

        // donut_encrypt
        chaskey::cipher::encrypt::<chaskey::core::ChaskeyLTS>(&mut x, &key);

        // XOR plaintext with ciphertext
        if length > 16 {
            r = 16;
        } else {
            r = length;
        }
        let mut i: usize = 0;
        while i < r as _ {
            x_u8 = from_u32x4(x);
            encrypted[p + i] ^= x_u8[i];
            i += 1;
        }

        // update length + position
        length -= r;
        p += r as usize;

        // update counter
        i = 16;
        while i > 0 {
            if ctr[i - 1] == std::u8::MAX {
                ctr[i - 1] = 0;
            } else {
                ctr[i - 1] += 1;
            }
            if ctr[i - 1] != 0 {
                break;
            }
            i -= 1;
        }
    }
    encrypted
}

pub fn rotr32(v: u32, n: u32) -> u32 {
    (v >> n) | (v << (32 - n))
}

pub fn speck(mk: [u8; MARU_BLK_LEN], p: u64) -> u64 {
    let mut w = [0u32; 2];
    let mut k = [0u32; 4];
    let mut t = 0u32;

    // copy 64bit plaintext to local buffer
    w = to_u32x2(&pack_u64(p));

    // copy 128bit master key to local buffer
    k = to_u32x4(&mk);

    for i in 0..27 {
        // encrypt 64bit plaintext
        w[0] = ((rotr32(w[0], 8) as usize + w[1] as usize) ^ k[0] as usize) as u32;
        w[1] = rotr32(w[1], 29) ^ w[0];

        // create next 32bit subkey
        t = k[3];
        k[3] = ((rotr32(k[1], 8) as usize + k[0] as usize) ^ i) as u32;
        k[0] = rotr32(k[0], 29) ^ k[3];
        k[1] = k[2];
        k[2] = t;
    }

    from_u32x2_u64(w)
}

#[allow(unused)]
pub fn maru(input: [u8; DONUT_MAX_NAME], iv: u64) -> u64 {
    let mut h = iv;
    let mut b = [0u8; MARU_BLK_LEN];

    // cut slice at first occurence of 0
    let zero_location = input.iter().position(|x| *x == 0).unwrap();
    let input = &input[0..zero_location];

    let (mut idx, mut length, mut end) = (0, 0, 0);
    loop {
        if end > 0 {
            break;
        }
        if length == input.len() || input[length] == 0 || length == MARU_MAX_STR {
            // zero remainder of M
            for j in idx..MARU_BLK_LEN {
                b[j] = 0;
            }
            // store the end bit
            b[idx] = 0x80;
            if idx >= MARU_BLK_LEN - 4 {
                h ^= speck(b, h);
                b = [0u8; MARU_BLK_LEN];
            }
            let tmp_b = pack((length * 8) as u32);
            b[12] = tmp_b[0];
            b[13] = tmp_b[1];
            b[14] = tmp_b[2];
            b[15] = tmp_b[3];
            idx = MARU_BLK_LEN;
            end += 1;
        } else {
            b[idx] = input[length];
            idx += 1;
            length += 1;
        }
        if idx == MARU_BLK_LEN {
            h ^= speck(b, h);
            idx = 0;
        }
    }
    h
}
