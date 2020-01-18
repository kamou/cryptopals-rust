extern crate base64;
extern crate openssl;


use std::fs;
use std::io::{BufRead, BufReader};
use std::error::Error;


use openssl::symm::decrypt;
use openssl::symm::{encrypt, Cipher};

static KEY: &'static [u8] = b"YELLOW SUBMARINE";


fn main () -> Result<(), Box<dyn Error>> {

    // read the file
    let filename = "7.txt";
    let file = fs::File::open(filename).unwrap();
    let reader = BufReader::new(file);

    // // Read the file line by line using the lines() iterator from std::io::BufRead.
    let mut cipher = "".to_owned();
    for line in reader.lines() {
        let line = line.unwrap(); // Ignore errors.
        cipher.push_str(&line);
    }

    let ciphertext = base64::decode(&cipher).unwrap();

    let cipher = Cipher::aes_128_ecb();
    let new_data = decrypt(cipher, KEY, None, &ciphertext[..]).unwrap();
    println!("{}", String::from_utf8(new_data).unwrap());


    Ok(())
}

   
