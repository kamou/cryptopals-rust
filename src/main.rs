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

    pub fn common_start_size(s1: &Vec<u8>, s2: &Vec<u8>) -> Option<usize>{
        let mut offset = 0;
        for (c1, c2) in s1.iter().zip(s2) {
            if c1-c2 != 0 {
                return Some(offset);
            }
            offset+=1;
        }
        None
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


        pub fn find_data_size_for_leak(&self) -> Option<(usize, usize)> {
            let block_size = self.detect_block_size();
            let mut pvec: Option<Vec<u8>> = None;
            let mut pcs: Option<usize> = None;
            for i in 0..block_size {
                let mut block = vec![0x41u8; 10 * block_size - i];
                let encrypted = self.blackbox(&block).unwrap();

                match pvec {
                    Some(v) => {
                        let cs = common_start_size(&v, &encrypted);
                        match pcs {
                            Some(_cs) => {
                                if cs.unwrap() != _cs {
                                    return Some((block.len(), _cs));
                                }
                            },
                            None => (),
                        };
                        pcs = Some(cs.unwrap());
                    },
                    _ => (),
                };
                pvec = Some(encrypted.clone(), );
            }
            None
        }

        // This function assumes constant data (or no data at all) is prepended to our input.
        // Only tested on CBC and EBC
        pub fn universal_leak(&self) -> Option<Vec<u8>> {
            let (psize, csize) = self.find_data_size_for_leak().expect("Can't leak.");
            println!("psize: {}, csize: {}", psize, csize);
            let block_size = self.detect_block_size();
            let mut pad = vec![0x41u8; psize];
            let mut data = vec![0x41u8; psize];
            let mut h: collections::HashMap<Vec<u8>, u8>;

            loop {
                h = self.last_byte_map(&data);

                let encrypted = self.blackbox(&pad).unwrap();
                pad.pop();
                match h.get(&encrypted[csize - block_size..csize]) {
                    None => break,
                    Some(v) => data.push(*v),
                };
                data = data[1..].to_vec();

            }
            Some(data)
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

        pub fn is_ecb(&self) -> bool{
            let block_size = self.detect_block_size();
            let data = vec![0x41u8;block_size*20];
            let ciphertext = self.blackbox(&data).expect("Failed to encrypt");
            let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
            for (i, b) in blocks.iter().enumerate() {
                if i > 0 {
                    if blocks[i-1] == *b {
                        return true;
                    }
                }
            }
            return false;

        }

        pub fn ecb_find_prepend_size(&self) -> usize {
            if !self.is_ecb() {
                panic!("not an ecb cipher.");
            }

            let block_size = self.detect_block_size();
            let data = vec![0x41u8;block_size*20];
            let ciphertext = self.blackbox(&data).expect("Failed to encrypt");
            let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
            let mut offset = None;
            for (i, b) in blocks.iter().enumerate() {
                if i > 0 {
                    if blocks[i-1] == *b {
                        println!("{:?}\n{:?}", &ciphertext[(i-1)*block_size..(i)*block_size], b);
                        offset = Some((i-1)*block_size);
                        break
                    }
                }
            }

            let offset = offset.unwrap();
            let pattern = &ciphertext[offset..offset+16];
            let data = vec![0x41u8; block_size];
            let mut n = 1;
            while n < block_size {
                let mut random_bytes = random(n);
                random_bytes.extend_from_slice(&data[..]);
                let result = self.blackbox(&random_bytes).unwrap();
                let mut i = 0;
                if &result[offset..offset+16] == pattern {
                    return offset - 16 + block_size - n;
                }
                n += 1;
            }
            0
        }

        pub fn last_byte_map(&self, data: &Vec<u8>) -> collections::HashMap<Vec<u8>, u8> {
            let (psize, csize) = self.find_data_size_for_leak().unwrap();
            let block_size = self.detect_block_size();
            let mut h: collections::HashMap<Vec<u8>, u8> = collections::HashMap::new();
            for i in 0..256 {
                let mut current = data.clone();
                current.push(i as u8);
                let k = self.blackbox(&current).expect("Failed to encrypt");
                h.insert(k[csize - block_size..csize].to_owned(), i as u8);
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

static RAND_DATA: OnceCell<Vec<u8>> = OnceCell::new();
static KEY: OnceCell<Vec<u8>> = OnceCell::new();

fn black_box(user_input: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
    static UNKNOWN_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let mut unknown_str = base64::decode(&UNKNOWN_B64).unwrap();
    let key = KEY.get().unwrap();
    let mut data = user_input.clone();
    let mut rng = rand::thread_rng();
    let mut prepad = match RAND_DATA.get() {
        None => {
            let rd = crypto_pals::random(rng.gen_range(17,31) as usize);
            RAND_DATA.set(rd.clone()).expect("Could not set RAND_DATA");
            rd
        },
        Some(rd) => rd.to_vec(),
    };

    data.append(&mut unknown_str);
    prepad.append(&mut data);

    let mut ct = Cipher::new(Algo::AES(CipherMode::ECB, 16));
    ct.set_key(key);
    ct.encrypt(&prepad)
}

fn challenge_14(at: &Attacker) {
    let leak = at.universal_leak().unwrap();
    println!("leak: {}", String::from_utf8(leak).unwrap());
}

fn main (){
    let key = crypto_pals::random(16);
    KEY.set(key.to_vec()).expect("Could not set KEY");
    let mut at = Attacker::new(&black_box);
    challenge_14(&at);
}
