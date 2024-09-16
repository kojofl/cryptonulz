macro_rules! impl_cryptoprovider {
    ( $($t:ty),+ ) => {
        $(
        impl Cryptoprovider for $t {
            fn encrypt(&self, buffer: &mut Vec<u8>) {
                let padding_len = BLOCKSIZE - (buffer.len() % BLOCKSIZE);
                buffer.extend(std::iter::repeat(padding_len as u8).take(padding_len));
                debug_assert!(buffer.len() % BLOCKSIZE == 0);
                for block in buffer.chunks_exact_mut(BLOCKSIZE) {
                    self.encrypt_block(
                        unsafe { &mut *(block as *mut [u8] as *mut [u8; BLOCKSIZE]) }
                        as &mut [u8; BLOCKSIZE],
                    );
                }
            }

            fn decrypt(&self, buffer: &mut Vec<u8>) {
                assert!(buffer.len() % BLOCKSIZE == 0);
                for block in buffer.chunks_exact_mut(BLOCKSIZE) {
                    self.decrypt_block(
                        unsafe { &mut *(block as *mut [u8] as *mut [u8; BLOCKSIZE]) }
                        as &mut [u8; BLOCKSIZE],
                    );
                }
                // empty buffer
                let Some(padding_len) = buffer.last() else {
                    return;
                };
                buffer.truncate(buffer.len() - *padding_len as usize);
            }

            fn encrypt_block(&self, block: &mut [u8; BLOCKSIZE]) {
                assert!(block.len() == BLOCKSIZE);
                let mut state = Matrix::from_values(&mut block[..]);
                add_round_key(&mut state, &self.expanded_key[0..16]);
                for round in 1..Self::ROUNDS {
                    sub_bytes(&mut state);
                    shift_rows(&mut state);
                    mix_collumns(&mut state);
                    add_round_key(
                        &mut state,
                        &self.expanded_key[round * BLOCKSIZE..(round + 1) * BLOCKSIZE],
                    );
                }
                sub_bytes(&mut state);
                shift_rows(&mut state);
                add_round_key(
                    &mut state,
                    &self.expanded_key[Self::ROUNDS * BLOCKSIZE..],
                );
            }

            fn decrypt_block(&self, block: &mut [u8; BLOCKSIZE]) {
                assert!(block.len() == BLOCKSIZE);
                let mut state = Matrix::from_values(&mut block[..]);
                add_round_key(
                    &mut state,
                    &self.expanded_key[Self::ROUNDS * BLOCKSIZE..(Self::ROUNDS + 1) * BLOCKSIZE],
                );
                for round in (1..Self::ROUNDS).into_iter().rev() {
                    inv_shift_rows(&mut state);
                    inv_sub_bytes(&mut state);
                    add_round_key(
                        &mut state,
                        &self.expanded_key[round * BLOCKSIZE..(round + 1) * BLOCKSIZE],
                    );
                    inv_mix_collumns(&mut state);
                }
                inv_shift_rows(&mut state);
                inv_sub_bytes(&mut state);
                add_round_key(&mut state, &self.expanded_key[..BLOCKSIZE]);
            }
        }
        )+
    };
}

pub(crate) use impl_cryptoprovider;
