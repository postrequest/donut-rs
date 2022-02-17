use crate::definitions::*;
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use rand::Rng;
use std::convert::TryInto;

pub fn random_string(size: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    let rand_string: String = (0..size)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    rand_string
}

pub fn to_array_donut_max_name(target: &str) -> [u8; DONUT_MAX_NAME] {
    if target.len() > DONUT_MAX_NAME {
        panic!("Exceeds DONUT_MAX_NAME length:\n{}", target);
    }
    to_array_usize(target)
}

pub fn to_array_usize<const N: usize>(target: &str) -> [u8; N] {
    let mut tmp = [0u8; N];
    for (i, byte) in target.bytes().enumerate() {
        tmp[i] = byte;
    }
    tmp
}

pub fn generate_bytes_16() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let rand_bytes: [u8; 16] = rng.gen();
    rand_bytes
}

pub fn generate_bytes<const N: usize>() -> [u8; N] {
    let mut rng = rand::thread_rng();
    let mut rand_bytes: [u8; N] = [0u8; N];
    for i in 0..N {
        rand_bytes[i] = rng.gen();
    }
    rand_bytes
}

pub fn array_to_u64(arr: [u8; 8]) -> u64 {
    let mut cur = std::io::Cursor::new(arr.to_vec());
    cur.read_u64::<LittleEndian>().unwrap()
}

pub fn array_to_u128(arr: [u8; 16]) -> u128 {
    let mut cur = std::io::Cursor::new(arr.to_vec());
    cur.read_u128::<LittleEndian>().unwrap()
}

// function similar to struct.pack from python3
pub fn pack(val: u32) -> [u8; 4] {
    let mut bytes = [0; 4];
    LittleEndian::write_u32(&mut bytes, val);
    bytes
}

pub fn pack_u64(val: u64) -> [u8; 8] {
    let mut bytes = [0; 8];
    LittleEndian::write_u64(&mut bytes, val);
    bytes
}

pub fn to_u32x4(bytes: &[u8; 16]) -> [u32; 4] {
    [
        LittleEndian::read_u32(&bytes[0..4]),
        LittleEndian::read_u32(&bytes[4..8]),
        LittleEndian::read_u32(&bytes[8..12]),
        LittleEndian::read_u32(&bytes[12..16]),
    ]
}

pub fn to_u32x2(bytes: &[u8; 8]) -> [u32; 2] {
    [
        LittleEndian::read_u32(&bytes[0..4]),
        LittleEndian::read_u32(&bytes[4..8]),
    ]
}

pub fn from_u32x2_u64(target: [u32; 2]) -> u64 {
    let mut tmp: Vec<u8> = Vec::new();
    for i in &target {
        tmp.extend(&i.to_le_bytes());
    }
    LittleEndian::read_u64(&tmp)
}

pub fn from_u32x4(target: [u32; 4]) -> [u8; 16] {
    let mut tmp: Vec<u8> = Vec::new();
    for i in &target {
        tmp.extend(&i.to_le_bytes());
    }
    tmp.try_into().expect("could not convert string to array")
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}
