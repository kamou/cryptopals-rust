extern crate base64;

use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};

fn pkcs7_add_padding (data: &mut Vec<u8>, bsize: usize) {
    let padding: usize = (bsize - data.len()) % bsize;
    let mut padding = vec![padding as u8; padding];
    data.append(&mut padding);
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

fn aes_cbc_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, iv: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    assert_eq!(key.len(), iv.len());

    let cipher_len = ciphertext.len();
    let num_blocks = cipher_len / block_size;
    let remaining  = cipher_len % block_size;

    let mut iv = iv.clone();
    let mut output = Vec::new();
    for bi in 0..num_blocks {
        let start = bi * block_size;
        let end   = (bi + 1) * block_size;

        let current_block = ciphertext[start..end].to_vec();

        let mut dblock = aes_128_decrypt(&current_block, key).unwrap();
        dblock = dblock.into_iter()
            .zip(iv)
            .map(|(dbv, ivv)| dbv^ivv)
            .collect();

        iv = current_block;

        output.append(&mut dblock);
    }

    if remaining != 0 {
        let mut current_block = ciphertext[(num_blocks * block_size)..].to_vec();
        pkcs7_add_padding(&mut current_block, block_size);
        let mut dblock = aes_128_decrypt(&current_block, key).unwrap();
        dblock = dblock.into_iter()
            .zip(iv)
            .map(|(dbv, ivv)| dbv^ivv)
            .collect();
        output.append(&mut dblock);
    }
    Ok(output)
}

fn main () -> Result<(), Box<dyn Error>> {
    let mut data = "YELLOW SUBMARINE".as_bytes().to_vec();
    pkcs7_add_padding(&mut data, 20);
    assert_eq!(data, [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4]);

    println!("pkcs7 done");
    let filename = "10.txt";
    let file = fs::File::open(filename).unwrap();
    let reader = BufReader::new(file);

     // Read the file line by line using the lines() iterator from std::io::BufRead.
    let mut cipher = "".to_owned();
    for line in reader.lines() {
        let line = line.unwrap(); // Ignore errors.
        cipher.push_str(&line);
    }
    let ciphertext = base64::decode(&cipher).expect("ta mere");

    let key = "YELLOW SUBMARINE".as_bytes().to_vec();
    let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec();
    let cleartext = aes_cbc_decrypt(&ciphertext, &key, &iv, 16).unwrap();
    println!("cleartext: {}", String::from_utf8(cleartext).expect(" tata "));
    Ok(())
}

   
