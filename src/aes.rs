use mightrix::{ColumnPrio, ColumnPrioMatrix, Reftrix, RowPrio, RowPrioMatrix, Stacktrix};

use crate::macros::debug_state;

type Matrix<'a> = Reftrix<'a, 4, 4, ColumnPrio, u8>;

const KEYSIZE_AES128: usize = 16;
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

const RCON_128: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const MIXMATRIX: Stacktrix<16, 4, 4, RowPrio, u8> =
    Stacktrix::with_values([2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2]);

pub trait Cryptoprovider {
    fn with_key(key: &[u8]) -> Self;
    fn encrypt(&self, block: Vec<u8>) -> Vec<u8>;
    fn decrypt(&self, block: Vec<u8>) -> Vec<u8>;
    fn encrypt_block(&self, buffer: &mut [u8]);
    fn decrypt_block(&self, buffer: &mut [u8]);
}

// Alg      kl bs  Nr
// AES-128   4  4  10
// AES-192   6  4  12
// AES-256   8  4  14

pub struct Aes128 {
    expanded_key: [u8; 176],
}

impl Aes128 {
    // Feature Flag
    // Openssl => duplicate decryption encryption with openssl
    fn key_expansion(key: &[u8]) -> Self {
        let mut expanded = [0; 44 * WORDSIZE];
        for mut i in 0..4 {
            i *= WORDSIZE;
            expanded[i] = key[i];
            expanded[i + 1] = key[i + 1];
            expanded[i + 2] = key[i + 2];
            expanded[i + 3] = key[i + 3];
        }
        let mut i = 4;
        while i < 44 {
            let (a, b) = expanded.split_at_mut(i * WORDSIZE);
            let (a, temp) = a.split_at_mut((i - 1) * WORDSIZE);
            let mut temp = temp.to_vec();
            if i % 4 == 0 {
                rot_word(&mut temp[..]);
                sub_word(&mut temp[..]);
                temp[0] ^= RCON_128[(i / 4) - 1];
            }
            b[0] = a[(i - 4) * WORDSIZE] ^ temp[0];
            b[1] = a[(i - 4) * WORDSIZE + 1] ^ temp[1];
            b[2] = a[(i - 4) * WORDSIZE + 2] ^ temp[2];
            b[3] = a[(i - 4) * WORDSIZE + 3] ^ temp[3];
            i += 1;
        }

        Self {
            expanded_key: expanded,
        }
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

impl Cryptoprovider for Aes128 {
    fn with_key(key: &[u8]) -> Self {
        assert_eq!(key.len(), KEYSIZE_AES128);
        Aes128::key_expansion(key)
    }

    fn encrypt(&self, _block: Vec<u8>) -> Vec<u8> {
        todo!()
    }

    fn decrypt(&self, _block: Vec<u8>) -> Vec<u8> {
        todo!()
    }

    fn encrypt_block(&self, buffer: &mut [u8]) {
        assert!(buffer.len() == BLOCKSIZE);
        let mut state = Matrix::from_values(&mut buffer[..]);
        add_round_key(&mut state, &self.expanded_key[0..16]);
        for round in 1..10 {
            debug_state!("Start of round:", &state);
            sub_bytes(&mut state);
            debug_state!("After sub_bytes:", &state);
            shift_rows(&mut state);
            debug_state!("After shift_rows:", &state);
            mix_collumns(&mut state);
            debug_state!("After mix_collumns:", &state);
            add_round_key(
                &mut state,
                &self.expanded_key[round * BLOCKSIZE..(round + 1) * BLOCKSIZE],
            );
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(
            &mut state,
            &self.expanded_key[10 * BLOCKSIZE..11 * BLOCKSIZE],
        );
    }

    fn decrypt_block(&self, buffer: &mut [u8]) {
        assert!(buffer.len() == BLOCKSIZE);
        let mut state = Matrix::from_values(&mut buffer[..]);
        add_round_key(&mut state, &self.expanded_key[0..16]);
        for round in 1..10 {
            sub_bytes(&mut state);
            inv_shift_rows(&mut state);
            mix_collumns(&mut state);
            add_round_key(
                &mut state,
                &self.expanded_key[round * BLOCKSIZE..(round + 1) * BLOCKSIZE],
            );
        }
        sub_bytes(&mut state);
        inv_shift_rows(&mut state);
        add_round_key(
            &mut state,
            &self.expanded_key[10 * BLOCKSIZE..11 * BLOCKSIZE],
        );
    }
}

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

fn mul_2(val: u8) -> u8 {
    let mo = (val & 0b10000000) != 0;
    let mut res = val << 1;
    if mo {
        res ^= 0x1b;
    }
    res
}

fn mul_3(val: u8) -> u8 {
    mul_2(val) ^ val
}

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

fn sub_bytes(state: &mut Matrix) {
    state.apply_all(|el| *el = SBOX[*el as usize]);
}

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
fn test_aes_128() {
    let key = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    let aes = Aes128::with_key(&key);
    let mut data = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];
    aes.encrypt_block(&mut data);
    assert_eq!(
        data,
        [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32
        ]
    )
}
