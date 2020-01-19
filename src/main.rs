extern crate base64;

use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};

extern crate rand;

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

fn aes_ecb_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
    let mut output = Vec::new();
    for current_block in blocks {
        let dblock = aes_128_decrypt(&current_block.to_vec(), key).unwrap();
        output.push(dblock);
    }
    Ok(output.concat())
}
fn aes_cbc_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let mut iv = iv.clone();
    let blocks: Vec<&[u8]> = ciphertext.chunks(block_size).collect();
    let mut output = Vec::new();
    for current_block in blocks {
        let current_block = current_block.to_vec();

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

fn encryption_oracle(input: &Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let key = random_key(16);

    let coin: bool = rng.gen();
    let pad_before: usize = rng.gen_range(5 , 11);
    let pad_after: usize = rng.gen_range(5, 11);

    let mut data = Vec::new();
    data.push(random_key(pad_before));
    data.push(input.to_vec());
    data.push(random_key(pad_after));

    let input = &data.concat();

    match coin {
        true => aes_ecb_encrypt(input, &key, 16).unwrap(),
        false => {
            let iv = random_key(16);
            aes_cbc_encrypt(input, &key, &iv, 16).unwrap()
        },
    }
}
enum BlockMode {
    CBC,
    ECB,
}

fn tell_block_mode() -> BlockMode {
    let data = encryption_oracle(&[0x41u8;64].to_vec());
    let first = &data[16..32];
    let second = &data[32..32+16];
    if first == second {
        return BlockMode::ECB;
    }
    return BlockMode::CBC;
}

fn main () -> Result<(), Box<dyn Error>> {
    println!("{}", match tell_block_mode() {
        BlockMode::CBC => "CBC",
        BlockMode::ECB => "ECB",

    });
    Ok(())
}

   
