use mightrix::{ColumnPrio, ColumnPrioMatrix, Reftrix, RowPrio, RowPrioMatrix, Stacktrix};

use crate::macros::impl_cryptoprovider;
use core::panic;

type Matrix<'a> = Reftrix<'a, 4, 4, ColumnPrio, u8>;

const EXPANDED_KEYSIZE_AES128: usize = 16 * 11;
const EXPANDED_KEYSIZE_AES192: usize = 16 * 13;
const EXPANDED_KEYSIZE_AES256: usize = 16 * 15;
const BLOCKSIZE: usize = 16;
const WORDSIZE: usize = 4;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INVSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON_128: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
const RCON_192: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
const RCON_258: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

const MIXMATRIX: Stacktrix<16, 4, 4, RowPrio, u8> =
    Stacktrix::with_values([2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]);

const INVMIXMATRIX: Stacktrix<16, 4, 4, RowPrio, u8> = Stacktrix::with_values([
    0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09, 0x0e,
]);

pub trait Cryptoprovider {
    fn encrypt(&self, block: &mut Vec<u8>);
    fn decrypt(&self, block: &mut Vec<u8>);
    fn encrypt_block(&self, buffer: &mut [u8; BLOCKSIZE]);
    fn decrypt_block(&self, buffer: &mut [u8; BLOCKSIZE]);
}

// Alg      kl bs  Nr
// AES-128   4  4  10
// AES-192   6  4  12
// AES-256   8  4  14

pub struct Aes128 {
    expanded_key: [u8; EXPANDED_KEYSIZE_AES128],
    padding: PaddingStrategy,
}
pub struct Aes192 {
    expanded_key: [u8; EXPANDED_KEYSIZE_AES192],
    padding: PaddingStrategy,
}
pub struct Aes256 {
    expanded_key: [u8; EXPANDED_KEYSIZE_AES256],
    padding: PaddingStrategy,
}

#[derive(Default)]
enum PaddingStrategy {
    #[default]
    PKCS7,
}

impl Aes128 {
    const ROUNDS: usize = 10;
    const KEYSIZE: usize = 16;
    const NK: usize = Self::KEYSIZE / 4;
    pub fn new(key: &[u8; Aes128::KEYSIZE]) -> Self {
        Self {
            expanded_key: Self::key_expansion(key),
            padding: Default::default(),
        }
    }
    fn key_expansion(key: &[u8; Aes128::KEYSIZE]) -> [u8; EXPANDED_KEYSIZE_AES128] {
        let mut expanded = [0; EXPANDED_KEYSIZE_AES128];
        expanded[..key.len()].copy_from_slice(key);
        for i in Self::NK..WORDSIZE * 11 {
            let (a, b) = expanded.split_at_mut(i * WORDSIZE);
            let (a, temp) = a.split_at_mut((i - 1) * WORDSIZE);
            let mut temp = temp.to_vec();
            if i % 4 == 0 {
                rot_word(&mut temp[..]);
                sub_word(&mut temp[..]);
                temp[0] ^= RCON_128[(i / (Self::KEYSIZE / 4)) - 1];
            }
            b[0] = a[(i - 4) * WORDSIZE] ^ temp[0];
            b[1] = a[(i - 4) * WORDSIZE + 1] ^ temp[1];
            b[2] = a[(i - 4) * WORDSIZE + 2] ^ temp[2];
            b[3] = a[(i - 4) * WORDSIZE + 3] ^ temp[3];
        }

        expanded
    }
}

impl Aes192 {
    const ROUNDS: usize = 12;
    const KEYSIZE: usize = 24;
    const NK: usize = Self::KEYSIZE / 4;
    pub fn new(key: &[u8; Aes192::KEYSIZE]) -> Self {
        Self {
            expanded_key: Self::key_expansion(key),
            padding: Default::default(),
        }
    }
    fn key_expansion(key: &[u8; Aes192::KEYSIZE]) -> [u8; EXPANDED_KEYSIZE_AES192] {
        let mut expanded = [0; EXPANDED_KEYSIZE_AES192];
        expanded[..key.len()].copy_from_slice(key);
        for i in Self::NK..WORDSIZE * 13 {
            let (a, b) = expanded.split_at_mut(i * WORDSIZE);
            let (a, temp) = a.split_at_mut((i - 1) * WORDSIZE);
            let mut temp = temp.to_vec();
            if i % Self::NK == 0 {
                rot_word(&mut temp[..]);
                sub_word(&mut temp[..]);
                temp[0] ^= RCON_192[(i / (Self::KEYSIZE / 4)) - 1];
            }
            b[0] = a[(i - Self::NK) * WORDSIZE] ^ temp[0];
            b[1] = a[(i - Self::NK) * WORDSIZE + 1] ^ temp[1];
            b[2] = a[(i - Self::NK) * WORDSIZE + 2] ^ temp[2];
            b[3] = a[(i - Self::NK) * WORDSIZE + 3] ^ temp[3];
        }

        expanded
    }
}

impl Aes256 {
    const ROUNDS: usize = 14;
    const KEYSIZE: usize = 32;
    const NK: usize = Self::KEYSIZE / 4;
    pub fn new(key: &[u8; Aes256::KEYSIZE]) -> Self {
        Self {
            expanded_key: Self::key_expansion(key),
            padding: Default::default(),
        }
    }

    fn key_expansion(key: &[u8; Aes256::KEYSIZE]) -> [u8; EXPANDED_KEYSIZE_AES256] {
        let mut expanded = [0; EXPANDED_KEYSIZE_AES256];
        expanded[..key.len()].copy_from_slice(key);
        for i in Self::NK..WORDSIZE * 15 {
            let (a, b) = expanded.split_at_mut(i * WORDSIZE);
            let (a, temp) = a.split_at_mut((i - 1) * WORDSIZE);
            let mut temp = temp.to_vec();
            if i % Self::NK == 0 {
                rot_word(&mut temp[..]);
                sub_word(&mut temp[..]);
                temp[0] ^= RCON_258[(i / (Self::KEYSIZE / 4)) - 1];
            } else if i % Self::NK == 4 {
                sub_word(&mut temp[..]);
            }
            b[0] = a[(i - Self::NK) * WORDSIZE] ^ temp[0];
            b[1] = a[(i - Self::NK) * WORDSIZE + 1] ^ temp[1];
            b[2] = a[(i - Self::NK) * WORDSIZE + 2] ^ temp[2];
            b[3] = a[(i - Self::NK) * WORDSIZE + 3] ^ temp[3];
        }

        expanded
    }
}

fn sub_word(word: &mut [u8]) {
    for el in word.iter_mut() {
        *el = SBOX[*el as usize];
    }
}

fn rot_word(word: &mut [u8]) {
    assert!(word.len() == 4);
    let (a, b) = word.split_at_mut(2);
    std::mem::swap(&mut a[0], &mut b[1]);
    std::mem::swap(&mut a[0], &mut b[0]);
    let (a, b) = a.split_at_mut(1);
    std::mem::swap(&mut a[0], &mut b[0]);
}

impl_cryptoprovider!(Aes128, Aes192, Aes256);

// impl Cryptoprovider for Aes128 {
//     fn encrypt(&self, buffer: &mut Vec<u8>) {
//         let padding_len = BLOCKSIZE - (buffer.len() % BLOCKSIZE);
//         buffer.extend(std::iter::repeat(padding_len as u8).take(padding_len));
//         debug_assert!(buffer.len() % BLOCKSIZE == 0);
//         for block in buffer.chunks_exact_mut(BLOCKSIZE) {
//             self.encrypt_block(
//                 unsafe { &mut *(block as *mut [u8] as *mut [u8; BLOCKSIZE]) }
//                     as &mut [u8; BLOCKSIZE],
//             );
//         }
//     }
//
//     fn decrypt(&self, buffer: &mut Vec<u8>) {
//         assert!(buffer.len() % BLOCKSIZE == 0);
//         for block in buffer.chunks_exact_mut(BLOCKSIZE) {
//             self.decrypt_block(
//                 unsafe { &mut *(block as *mut [u8] as *mut [u8; BLOCKSIZE]) }
//                     as &mut [u8; BLOCKSIZE],
//             );
//         }
//         // empty buffer
//         let Some(padding_len) = buffer.last() else {
//             return;
//         };
//         buffer.truncate(buffer.len() - *padding_len as usize);
//     }
//
//     fn encrypt_block(&self, block: &mut [u8; BLOCKSIZE]) {
//         assert!(block.len() == BLOCKSIZE);
//         let mut state = Matrix::from_values(&mut block[..]);
//         add_round_key(&mut state, &self.expanded_key[0..16]);
//         for round in 1..10 {
//             debug_state!("Start of round:", &state);
//             sub_bytes(&mut state);
//             debug_state!("After sub_bytes:", &state);
//             shift_rows(&mut state);
//             debug_state!("After shift_rows:", &state);
//             mix_collumns(&mut state);
//             debug_state!("After mix_collumns:", &state);
//             add_round_key(
//                 &mut state,
//                 &self.expanded_key[round * BLOCKSIZE..(round + 1) * BLOCKSIZE],
//             );
//         }
//         sub_bytes(&mut state);
//         shift_rows(&mut state);
//         add_round_key(
//             &mut state,
//             &self.expanded_key[10 * BLOCKSIZE..11 * BLOCKSIZE],
//         );
//     }
//
//     fn decrypt_block(&self, block: &mut [u8; BLOCKSIZE]) {
//         assert!(block.len() == BLOCKSIZE);
//         let mut state = Matrix::from_values(&mut block[..]);
//         debug_state!("Init:", &state);
//         add_round_key(
//             &mut state,
//             &self.expanded_key[10 * BLOCKSIZE..11 * BLOCKSIZE],
//         );
//         for round in (1..10).into_iter().rev() {
//             debug_state!("Start of round:", &state);
//             inv_shift_rows(&mut state);
//             debug_state!("After shift_rows:", &state);
//             inv_sub_bytes(&mut state);
//             debug_state!("After sub_bytes:", &state);
//             add_round_key(
//                 &mut state,
//                 &self.expanded_key[round * BLOCKSIZE..(round + 1) * BLOCKSIZE],
//             );
//             debug_state!("After round key:", &state);
//             inv_mix_collumns(&mut state);
//         }
//         inv_shift_rows(&mut state);
//         inv_sub_bytes(&mut state);
//         add_round_key(&mut state, &self.expanded_key[..16]);
//     }
// }

#[doc(hidden)]
fn mix_collumns(state: &mut Matrix) {
    let mut new_col = [0; 4];
    for i in 0..4 {
        let col = state.get_mut_column(i);
        for j in 0..4 {
            let mix_row = MIXMATRIX.get_row(j);
            let mut new_val = match mix_row[0] {
                1 => col[0],
                2 => mul_2(col[0]),
                3 => mul_3(col[0]),
                _ => {
                    panic!("The MIXMATRIX only has values form 1..=3")
                }
            };
            for x in 1..4 {
                new_val ^= match mix_row[x] {
                    1 => col[x],
                    2 => mul_2(col[x]),
                    3 => mul_3(col[x]),
                    _ => {
                        panic!("The MIXMATRIX only has values form 1..=3")
                    }
                };
            }
            new_col[j] = new_val;
        }
        for (old, new) in col.into_iter().zip(new_col.into_iter()) {
            *old = new;
        }
    }
}

#[doc(hidden)]
fn inv_mix_collumns(state: &mut Matrix) {
    let mut new_col = [0; 4];
    for i in 0..4 {
        let col = state.get_mut_column(i);
        for j in 0..4 {
            let mix_row = INVMIXMATRIX.get_row(j);
            let mut new_val = match mix_row[0] {
                9 => mul_9(col[0]),
                11 => mul_11(col[0]),
                13 => mul_13(col[0]),
                14 => mul_14(col[0]),
                _ => {
                    panic!("The MIXMATRIX only has values [9, 11, 13, 14]")
                }
            };
            for x in 1..4 {
                new_val ^= match mix_row[x] {
                    9 => mul_9(col[x]),
                    11 => mul_11(col[x]),
                    13 => mul_13(col[x]),
                    14 => mul_14(col[x]),
                    _ => {
                        panic!("The MIXMATRIX only has values [9, 11, 13, 14]")
                    }
                };
            }
            new_col[j] = new_val;
        }
        for (old, new) in col.into_iter().zip(new_col.into_iter()) {
            *old = new;
        }
    }
}

#[inline(always)]
#[doc(hidden)]
fn mul_2(val: u8) -> u8 {
    dbl(val)
}

#[inline(always)]
#[doc(hidden)]
fn mul_3(val: u8) -> u8 {
    dbl(val) ^ val
}

#[inline(always)]
#[doc(hidden)]
fn mul_9(val: u8) -> u8 {
    return dbl(dbl(dbl(val))) ^ val;
}

#[inline(always)]
#[doc(hidden)]
fn mul_11(val: u8) -> u8 {
    let a2 = dbl(val);
    let a4 = dbl(a2);
    let a8 = dbl(a4);
    return a8 ^ a2 ^ val;
}

#[inline(always)]
#[doc(hidden)]
fn mul_13(val: u8) -> u8 {
    let a2 = dbl(val);
    let a4 = dbl(a2);
    let a8 = dbl(a4);
    return a8 ^ a4 ^ val;
}

#[inline(always)]
#[doc(hidden)]
fn mul_14(val: u8) -> u8 {
    let a2 = dbl(val);
    let a4 = dbl(a2);
    let a8 = dbl(a4);
    return a8 ^ a4 ^ a2;
}

#[inline(always)]
#[doc(hidden)]
fn dbl(val: u8) -> u8 {
    let val = val as u16;
    ((val << 1) ^ (0x200 - ((val & 0x80) >> 7)) & 0x11b) as u8
}

#[doc(hidden)]
fn shift_rows(state: &mut Matrix) {
    // 1, 2, 3, 4 -> 2, 3, 4, 1
    let mut first_row = state.get_mut_row(1);
    first_row.swap(0, 3);
    first_row.swap(0, 2);
    first_row.swap(0, 1);
    // 1, 2, 3, 4 -> 3, 4, 1, 2
    let mut second_row = state.get_mut_row(2);
    second_row.swap(0, 2);
    second_row.swap(1, 3);
    // 1, 2, 3, 4 -> 4, 1, 2, 3
    let mut third_row = state.get_mut_row(3);
    third_row.swap(0, 3);
    third_row.swap(1, 2);
    third_row.swap(1, 3);
}

#[doc(hidden)]
fn inv_shift_rows(state: &mut Matrix) {
    // 1, 2, 3, 4 -> 4, 1, 2, 3
    let mut first_row = state.get_mut_row(1);
    first_row.swap(0, 3);
    first_row.swap(1, 3);
    first_row.swap(2, 3);
    // 1, 2, 3, 4 -> 3, 4, 1, 2
    let mut second_row = state.get_mut_row(2);
    second_row.swap(0, 2);
    second_row.swap(1, 3);
    // 1, 2, 3, 4 -> 2, 3, 4, 1
    let mut third_row = state.get_mut_row(3);
    third_row.swap(0, 3);
    third_row.swap(0, 2);
    third_row.swap(0, 1);
}

#[doc(hidden)]
fn inv_sub_bytes(state: &mut Matrix) {
    state.apply_all(|el| *el = INVSBOX[*el as usize]);
}

#[doc(hidden)]
fn sub_bytes(state: &mut Matrix) {
    state.apply_all(|el| *el = SBOX[*el as usize]);
}

#[doc(hidden)]
fn add_round_key(state: &mut Matrix, key: &[u8]) {
    assert_eq!(key.len(), 16);
    for i in 0..4 {
        let col = state.get_mut_column(i);
        for (j, el) in col.into_iter().enumerate() {
            *el ^= key[WORDSIZE * i + j];
        }
    }
}

#[test]
fn test_aes_128_encryption() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let aes = Aes128::new(&key);
    let mut data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    aes.encrypt_block(&mut data);
    assert_eq!(
        data,
        [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ]
    )
}

#[test]
fn test_aes_128_decryption() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let aes = Aes128::new(&key);
    let mut data = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    aes.decrypt_block(&mut data);
    assert_eq!(
        data,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
    )
}

#[test]
fn test_aes_128() {
    let key = b"TopSecretPasswor";
    let aes = Aes128::new(key);
    let mut data = b"NulzIstEinHund!!".to_vec();
    aes.encrypt_block(data.as_mut_slice().try_into().unwrap());
    assert_ne!(data, b"NulzIstEinHund!!");
    aes.decrypt_block(data.as_mut_slice().try_into().unwrap());
    assert_eq!(data, b"NulzIstEinHund!!");
}

#[test]
fn test_aes_128_with_padding() {
    let key = b"TopSecretPasswor";
    let aes = Aes128::new(key);
    let mut data = b"This is a super secret text that no one should read!".to_vec();
    aes.encrypt(&mut data);
    assert_ne!(
        data,
        b"This is a super secret text that no one should read!"
    );
    aes.decrypt(&mut data);
    assert_eq!(
        data,
        b"This is a super secret text that no one should read!"
    );
}

#[test]
fn test_aes_128_key_expansion() {
    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let aes = Aes128::new(&key);
    assert_eq!(
        aes.expanded_key,
        [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39,
            0x2a, 0x6c, 0x76, 0x05, 0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35,
            0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f, 0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e,
            0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b, 0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52,
            0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00, 0xd4, 0xd1, 0xc6, 0xf8,
            0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc, 0x6d, 0x88,
            0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,
            0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6,
            0xdc, 0x4f, 0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60,
            0x7f, 0x8d, 0x29, 0x2f, 0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1,
            0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e, 0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89,
            0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6
        ]
    );
}

#[test]
fn test_aes_192_key_expansion() {
    let key = [
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79,
        0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    ];
    let aes = Aes192::new(&key);
    assert_eq!(
        aes.expanded_key,
        [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b, 0xfe, 0x0c, 0x91, 0xf7,
            0x24, 0x02, 0xf5, 0xa5, 0xec, 0x12, 0x06, 0x8e, 0x6c, 0x82, 0x7f, 0x6b, 0x0e, 0x7a,
            0x95, 0xb9, 0x5c, 0x56, 0xfe, 0xc2, 0x4d, 0xb7, 0xb4, 0xbd, 0x69, 0xb5, 0x41, 0x18,
            0x85, 0xa7, 0x47, 0x96, 0xe9, 0x25, 0x38, 0xfd, 0xe7, 0x5f, 0xad, 0x44, 0xbb, 0x09,
            0x53, 0x86, 0x48, 0x5a, 0xf0, 0x57, 0x21, 0xef, 0xb1, 0x4f, 0xa4, 0x48, 0xf6, 0xd9,
            0x4d, 0x6d, 0xce, 0x24, 0xaa, 0x32, 0x63, 0x60, 0x11, 0x3b, 0x30, 0xe6, 0xa2, 0x5e,
            0x7e, 0xd5, 0x83, 0xb1, 0xcf, 0x9a, 0x27, 0xf9, 0x39, 0x43, 0x6a, 0x94, 0xf7, 0x67,
            0xc0, 0xa6, 0x94, 0x07, 0xd1, 0x9d, 0xa4, 0xe1, 0xec, 0x17, 0x86, 0xeb, 0x6f, 0xa6,
            0x49, 0x71, 0x48, 0x5f, 0x70, 0x32, 0x22, 0xcb, 0x87, 0x55, 0xe2, 0x6d, 0x13, 0x52,
            0x33, 0xf0, 0xb7, 0xb3, 0x40, 0xbe, 0xeb, 0x28, 0x2f, 0x18, 0xa2, 0x59, 0x67, 0x47,
            0xd2, 0x6b, 0x45, 0x8c, 0x55, 0x3e, 0xa7, 0xe1, 0x46, 0x6c, 0x94, 0x11, 0xf1, 0xdf,
            0x82, 0x1f, 0x75, 0x0a, 0xad, 0x07, 0xd7, 0x53, 0xca, 0x40, 0x05, 0x38, 0x8f, 0xcc,
            0x50, 0x06, 0x28, 0x2d, 0x16, 0x6a, 0xbc, 0x3c, 0xe7, 0xb5, 0xe9, 0x8b, 0xa0, 0x6f,
            0x44, 0x8c, 0x77, 0x3c, 0x8e, 0xcc, 0x72, 0x04, 0x01, 0x00, 0x22, 0x02,
        ]
    );
}

#[test]
fn test_aes_aes192_encryption() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    let aes = Aes192::new(&key);
    let mut data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    aes.encrypt_block(&mut data);
    assert_eq!(
        data,
        [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ]
    )
}

#[test]
fn test_aes_aes192_decryption() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];
    let aes = Aes192::new(&key);
    let mut data = [
        0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71,
        0x91,
    ];
    aes.decrypt_block(&mut data);
    assert_eq!(
        data,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
    )
}

// #[test]
// fn test_aes_256_key_expansion() {
//     let key = [
//         0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
//         0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
//         0xdf, 0xf4,
//     ];
//     let aes = Aes256::new(&key);
//     panic!("{:0x?}", aes.expanded_key);
// }

#[test]
fn test_aes_aes256_encryption() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let aes = Aes256::new(&key);
    let mut data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    aes.encrypt_block(&mut data);
    assert_eq!(
        data,
        [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ]
    )
}

#[test]
fn test_aes_aes256_decryption() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let aes = Aes256::new(&key);
    let mut data = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];
    aes.decrypt_block(&mut data);
    assert_eq!(
        data,
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]
    )
}
