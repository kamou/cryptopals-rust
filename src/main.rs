extern crate base64;
extern crate rand;

use std::collections;
use rand::Rng;

fn pkcs7_add_padding (data: &Vec<u8>, bsize: usize) -> Vec<u8> {
    let padding: usize = (bsize - data.len()) % bsize;
    let mut padding = vec![padding as u8; padding];
    let mut data = data.clone();
    data.append(&mut padding);
    data
}

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes128;

fn aes_128_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let key = GenericArray::from_slice(&key[0..16]);
    let mut block = GenericArray::clone_from_slice(&ciphertext[0..16]);

    // Initialize cipher
    let cipher = Aes128::new(&key);
    cipher.decrypt_block(&mut block);
    Ok(block.to_vec())
}

fn aes_128_encrypt(cleartext: &Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let key = GenericArray::from_slice(&key[0..16]);
    let mut block = GenericArray::clone_from_slice(&cleartext[0..16]);

    // Initialize cipher
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);
    Ok(block.to_vec())
}

fn aes_ecb_encrypt(plaintext: &Vec<u8>, key: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let blocks: Vec<&[u8]> = plaintext.chunks(block_size).collect();
    let mut output: Vec<Vec<u8>> = Vec::new();
    for current_block in blocks {
        let mut current_block = current_block.to_owned();
        if current_block.len() != block_size {
            current_block = pkcs7_add_padding(&current_block, block_size).clone();
        }
        let eblock = aes_128_encrypt(&current_block, key).unwrap();
        output.push(eblock);
    }
    Ok(output.concat())
}

#[allow(dead_code)]
fn aes_cbc_encrypt(plaintext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let mut iv = iv.clone();
    let blocks: Vec<&[u8]> = plaintext.chunks(block_size).collect();
    let mut output = Vec::new();
    for current_block in blocks {
        let mut current_block = current_block.to_owned();
        if current_block.len() != block_size {
            current_block = pkcs7_add_padding(&current_block, block_size).clone();
        }
        let current_block = current_block.into_iter()
            .zip(iv)
            .map(|(dbv, ivv)| dbv^ivv)
            .collect();

        let eblock = aes_128_encrypt(&current_block, key).unwrap();
        iv = eblock.to_owned();
        output.push(eblock);
    }
    Ok(output.concat())
}

#[allow(dead_code)]
fn aes_ecb_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
    let mut output = Vec::new();
    for current_block in blocks {
        let dblock = aes_128_decrypt(&current_block.to_owned(), key).unwrap();
        output.push(dblock);
    }
    Ok(output.concat())
}

#[allow(dead_code)]
fn aes_cbc_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let mut iv = iv.clone();
    let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
    let mut output = Vec::new();
    for current_block in blocks {
        let current_block = current_block.to_owned();

        let dblock: Vec<u8> = aes_128_decrypt(&current_block, key)
            .unwrap()
            .into_iter()
            .zip(iv)
            .map(|(dbv, ivv)| dbv^ivv)
            .collect();

        iv = current_block;
        output.push(dblock);
    }
    Ok(output.concat())
}

fn random_key(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    vec![0u8;size]
        .into_iter()
        .map(|_| rng.gen())
        .collect()
} 

fn black_box_unknown_key(user_input: &Vec<u8>, block_size: usize) -> Vec<u8> {
    let key = random_key(block_size);
    let data = user_input.clone();

    black_box(&data, &key, block_size)
}

fn black_box(user_input: &Vec<u8>, key: &Vec<u8>, block_size: usize) -> Vec<u8> {
    static UNKNOWN_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let mut unknown_str = base64::decode(&UNKNOWN_B64).unwrap();
    let mut data = user_input.clone();

    data.append(&mut unknown_str);
    aes_ecb_encrypt(&data, &key, block_size).unwrap()
}

fn detect_block_size(encryptor: &dyn Fn(&Vec<u8>, usize) -> Vec<u8>) -> usize {
    let mut pval: Option<usize> = None;
    let mut data = vec![0x41u8];
    return loop {
        let decrypted = encryptor(&data, 16);
        let cur_len = decrypted.len();
        match pval {
            Some(v) if cur_len - v != 0 => break cur_len - v,
            _ => pval = Some(cur_len),
        };
        data.push(0x41);
    };
}

fn get_enc_dec_map(data: &Vec<u8>, encryptor: &dyn Fn(&Vec<u8>, &Vec<u8>, usize) -> Vec<u8>, key: &Vec<u8>, block_size: usize, num_blocks: usize) -> collections::HashMap<Vec<u8>, u8> {
    let mut h: collections::HashMap<Vec<u8>, u8> = collections::HashMap::new();
    for i in 0..256 {
        let mut current = data[1..].to_vec();
        current.push(i as u8);
        let k = encryptor(&current, &key, 16);
        h.insert(k[(num_blocks-1)*block_size..num_blocks*block_size].to_owned(), i as u8);
    }
    h
}

fn main (){
    let block_size = detect_block_size(&black_box_unknown_key);
    println!("block size: {}", block_size);

    let key = random_key(16);
    let mut pad = vec![0x41u8; 10*block_size];
    let mut data = vec![0x41u8; 10*block_size];
    let mut h: collections::HashMap<Vec<u8>, u8>;

    loop {
        h = get_enc_dec_map(&data, &black_box, &key, 16, 10);
        pad.pop();

        let encrypted = black_box(&pad, &key, 16);
        match h.get(&encrypted[9*block_size..10*block_size]) {
            None => break,
            Some(v) => data.push(*v),
        };
        data = data[1..].to_vec();
    }
    println!("{}", String::from_utf8(data).unwrap());
}
