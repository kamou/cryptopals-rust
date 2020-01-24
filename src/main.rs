extern crate base64;
extern crate rand;

use std::collections;
use once_cell::sync::OnceCell;

mod crypto_pals {
    use rand::Rng;
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;
    use aes::{Aes128, Aes192, Aes256};
    use std::collections;

    pub fn random(size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        vec![0u8;size]
            .into_iter()
            .map(|_| rng.gen())
            .collect()
    }

    pub enum CipherMode {
        ECB,
        CBC(Vec<u8>),
    }

    pub struct Attacker {
        _blackbox: Option<&'static dyn std::ops::Fn(&Vec<u8>) -> Result<Vec<u8>, &'static str>>,
    }

    impl Attacker {
        pub fn new(f: &'static dyn std::ops::Fn(&Vec<u8>) -> Result<Vec<u8>, &'static str>) -> Attacker {
            Attacker {
                _blackbox: Some(f),
            }
        }

        pub fn ecb_block_size_after_padding(&self, size: usize) -> usize {
            let block_size = self.detect_block_size();
            let mut data = vec![0x41u8; size];
            let ciphertext = self.blackbox(&data).expect("Failed to encrypt");
            let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
            let mut pval: Option<Vec<u8>> = None;
            let mut i: u32 = 0;

            // find first and last consecutive equal chunks
            let mut blocks = blocks.iter();
            let mut first: Option<u32> = None;
            let last = loop {
                let current_block = match blocks.next() {
                    Some(b) => b.to_vec(),
                    None => break None,
                };

                match pval {
                    Some(v) if (!(v == current_block) && (first != None))
                        => {pval = Some(v); break Some(i);},
                        Some(v) if ((v == current_block) && (first == None))
                            => first = Some(i-1),
                        _ => (),
                };
                pval = Some(current_block);
                i+=1;
            };

            let pv = pval.unwrap().to_vec();
            let last = last.expect("Can't find correct size");

            // increase data size until last block is equal to previous block
            loop {
                data.push(0x41);
                let ciphertext = self.blackbox(&data).unwrap();
                let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
                if blocks[last as usize].to_vec() == pv {
                    return data.len();
                }
            }
        }

        pub fn detect_block_size(&self) -> usize {
            let mut pval: Option<usize> = None;
            let mut data = vec![0x41u8];
            return loop {
                let encrypted = self.blackbox(&data).expect("Failed to encrypt");
                let cur_len = encrypted.len();
                match pval {
                    Some(v) if cur_len - v != 0 => break cur_len - v,
                    _ => pval = Some(cur_len),
                };
                data.push(0x41);
            };
        }

        pub fn ecb_last_byte_map(&self, data: &Vec<u8>) -> collections::HashMap<Vec<u8>, u8> {
            let block_size = self.detect_block_size();
            let mut h: collections::HashMap<Vec<u8>, u8> = collections::HashMap::new();
            for i in 0..256 {
                let mut current = data[1..].to_vec();
                current.push(i as u8);
                let k = self.blackbox(&current).expect("Failed to encrypt");
                h.insert(k[current.len() - 1 - block_size..current.len() - 1].to_owned(), i as u8);
            }
            h
        }

        pub fn set_blackbox(&mut self, blackbox: &'static dyn std::ops::Fn(&Vec<u8>) -> Result<Vec<u8>, &'static str>) {
            self._blackbox = Some(blackbox);
        }

        pub fn blackbox(&self, data: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
            let f = self._blackbox.unwrap();
            f(data)
        }

    }

    pub enum Algo {
        AES(CipherMode, usize),
    }

    pub struct Cipher {
        key: Vec<u8>,
        algo: Algo,
    }

    impl Cipher {
        pub fn new(algo: Algo) -> Cipher {
            Cipher {
                algo: algo,
                key: Vec::new(),
            }
        }

        fn ecb_detect_block_size(&self, encryptor: &'static dyn std::ops::Fn(&Vec<u8>) -> Result<Vec<u8>, &'static str>) -> usize {
            let mut pval: Option<usize> = None;
            let mut data = vec![0x41u8];
            return loop {
                let encrypted = encryptor(&data).expect("Failed to encrypt");
                let cur_len = encrypted.len();
                match pval {
                    Some(v) if cur_len - v != 0 => break cur_len - v,
                    _ => pval = Some(cur_len),
                };
                data.push(0x41);
            };
        }

        pub fn set_key(&mut self, key: &Vec<u8>) {
            self.key.clear();
            self.key.extend(key);
        }

        pub fn decrypt(&self, data: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
            match &self.algo {
                Algo::AES(mode, size) => match mode {
                    CipherMode::ECB => self.aes_ecb_decrypt(data, *size),
                    CipherMode::CBC(iv) => self.aes_cbc_decrypt(data, iv, *size),
                }
            }
        }

        pub fn encrypt(&self, data: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
            match &self.algo {
                Algo::AES(mode, size) => match mode {
                    CipherMode::ECB => self.aes_ecb_encrypt(data, *size),
                    CipherMode::CBC(iv) => self.aes_cbc_encrypt(data, iv, *size),
                },
            }
        }

        fn aes_decrypt(&self, ciphertext: &Vec<u8>, size: usize) -> Result<Vec<u8>, &'static str> {
            let result;
            match size {
                16 => {
                    let mut block = GenericArray::clone_from_slice(&ciphertext[0..size]);
                    let key = GenericArray::from_slice(&self.key[0..size]);
                    Aes128::new(key).decrypt_block(&mut block);
                    result = block;
                },
                24 => {
                    let mut block = GenericArray::clone_from_slice(&ciphertext[0..size]);
                    let key = GenericArray::from_slice(&self.key[0..size]);
                    Aes192::new(key).decrypt_block(&mut block);
                    result = block;
                },
                32 => {
                    let mut block = GenericArray::clone_from_slice(&ciphertext[0..size]);
                    let key = GenericArray::from_slice(&self.key[0..size]);
                    Aes256::new(key).decrypt_block(&mut block);
                    result = block;
                },
                _ =>
                    panic!("aes block size not supported")
            };
            assert!(Cipher::pkcs7_valid(&result.to_vec(), size));
            Ok(result.to_vec())
        }

        fn aes_encrypt(&self, plaintext: &Vec<u8>, size: usize) -> Result<Vec<u8>, &'static str> {
            let result;
            match size {
                16 => {
                    let mut block = GenericArray::clone_from_slice(&plaintext[0..size]);
                    let key = GenericArray::from_slice(&self.key[0..size]);
                    Aes128::new(key).encrypt_block(&mut block);
                    result = block;
                },
                24 => {
                    let mut block = GenericArray::clone_from_slice(&plaintext[0..size]);
                    let key = GenericArray::from_slice(&self.key[0..size]);
                    Aes192::new(key).encrypt_block(&mut block);
                    result = block;
                },
                32 => {
                    let mut block = GenericArray::clone_from_slice(&plaintext[0..size]);
                    let key = GenericArray::from_slice(&self.key[0..size]);
                    Aes256::new(key).encrypt_block(&mut block);
                    result = block;
                },
                _ =>
                    panic!("aes block size not supported")
            };
            Ok(result.to_vec())
        }

        fn aes_ecb_decrypt(&self, ciphertext: &Vec<u8>, size: usize) -> Result<Vec<u8>, &'static str> {
            let blocks: Vec<&[u8]> = ciphertext.chunks(size).collect();
            let mut output = Vec::new();
            for current_block in blocks {
                let dblock = self.aes_decrypt(&current_block.to_owned(), size)?;
                output.push(dblock);
            }
            Ok(output.concat())
        }

        fn aes_cbc_decrypt(&self, ciphertext: &Vec<u8>, iv: &Vec<u8>, size: usize) -> Result<Vec<u8>, &'static str> {

            let mut iv = iv.clone();
            let blocks: Vec<&[u8]> = ciphertext.chunks(size).collect();
            let mut output = Vec::new();
            for current_block in blocks {
                let current_block = current_block.to_owned();

                let dblock: Vec<u8> = self.aes_decrypt(&current_block, size)?
                    .into_iter()
                    .zip(iv)
                    .map(|(dbv, ivv)| dbv^ivv)
                    .collect();

                iv = current_block;
                output.push(dblock);
            }
            Ok(output.concat())
        }

        fn aes_ecb_encrypt(&self, plaintext: &Vec<u8>, size: usize) -> Result<Vec<u8>, &'static str> {
            let blocks: Vec<&[u8]> = plaintext.chunks(size).collect();
            let mut output: Vec<Vec<u8>> = Vec::new();
            for current_block in blocks {
                let mut current_block = current_block.to_owned();
                if current_block.len() != size {
                    current_block = Cipher::pkcs7_add_padding(&current_block, size);
                }
                let eblock = self.aes_encrypt(&current_block, size)?;
                output.push(eblock);
            }
            let output = output.concat();
            Ok(output)
        }

        fn aes_cbc_encrypt(&self, plaintext: &Vec<u8>, iv: &Vec<u8>, size: usize) -> Result<Vec<u8>, &'static str> {
            let mut iv = iv.clone();
            let blocks: Vec<&[u8]> = plaintext.chunks(size).collect();
            let mut output = Vec::new();
            for current_block in blocks {
                let mut current_block = current_block.to_owned();
                if current_block.len() != size {
                    current_block = Cipher::pkcs7_add_padding(&current_block, size);
                }
                let current_block = current_block.into_iter()
                    .zip(iv)
                    .map(|(dbv, ivv)| dbv^ivv)
                    .collect();

                let eblock = self.aes_encrypt(&current_block, size)?;
                iv = eblock.to_owned();
                output.push(eblock);
            }
            Ok(output.concat())
        }

        pub fn pkcs7_add_padding (data: &Vec<u8>, size: usize) -> Vec<u8> {
            let padding: usize = (size - data.len()) % size;
            let mut padding = vec![padding as u8; padding];
            let mut data = data.clone();
            data.append(&mut padding);
            data
        }

        pub fn pkcs7_valid (data: &Vec<u8>, size: usize) -> bool {
            let len = data.len();
            let last = data.last().unwrap();
            for c in &data[data.len() - 1 - *last as usize..] {
                if c != last { 
                    return false;
                }
            }
            let prev = data[data.len() - 1 - *last as usize - 1];
            for c in &data[data.len() - 1 - *last as usize - prev as usize..] {
                if *c != prev { 
                    return false;
                }
            }
            true
        }

    }
}

use crypto_pals::{Cipher, Algo, CipherMode, Attacker};
use rand::Rng;

fn black_box_unknown_key(user_input: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let key = crypto_pals::random(block_size);
    let data = user_input.clone();

    black_box_with_key(&data, &key, block_size)
}

static RAND_DATA: OnceCell<Vec<u8>> = OnceCell::new();
static KEY: OnceCell<Vec<u8>> = OnceCell::new();

fn black_box_with_key(user_input: &Vec<u8>, key: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    static UNKNOWN_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let mut unknown_str = base64::decode(&UNKNOWN_B64).unwrap();
    let mut data = user_input.clone();
    let mut rng = rand::thread_rng();
    let mut prepad = match RAND_DATA.get() {
        None => {
            let rd = crypto_pals::random(rng.gen_range(5,11) as usize);
            RAND_DATA.set(rd.clone()).expect("Could not set RAND_DATA");
            rd
        },
        Some(rd) => rd.to_vec(),
    };

    data.append(&mut unknown_str);
    prepad.append(&mut data);

    let mut ct = Cipher::new(Algo::AES(CipherMode::ECB, block_size));
    ct.set_key(key);
    // ct.set_blackbox(&black_box);
    ct.encrypt(&prepad)
}
fn black_box(user_input: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let key = KEY.get().unwrap();
    black_box_with_key(&user_input, &key, 16)
}

fn challenge_14(at: &Attacker) {
    let block_size = at.detect_block_size();
    println!("block size: {}", block_size);

    let data_size = at.ecb_block_size_after_padding(block_size * 10);
    let mut pad = vec![0x41u8; data_size];
    let mut data = vec![0x41u8; data_size];
    let mut h: collections::HashMap<Vec<u8>, u8>;

    loop {
        h = at.ecb_last_byte_map(&data);
        pad.pop();

        let encrypted = at.blackbox(&pad).unwrap();
        match h.get(&encrypted[data_size - 1 - block_size..data_size-1]) {
            None => break,
            Some(v) => data.push(*v),
        };
        data = data[1..].to_vec();

    }
    println!("{}", String::from_utf8(data).unwrap());
}

fn main (){
    let key = crypto_pals::random(16);
    KEY.set(key.to_vec()).expect("Could not set KEY");

    let mut at = Attacker::new(&black_box);
    let block_size = at.detect_block_size();

    // let mut ct = Cipher::new(Algo::AES(CipherMode::ECB, block_size));
    // ct.set_key(&key);
    // at.set_blackbox(&black_box);
    challenge_14(&at);
}
