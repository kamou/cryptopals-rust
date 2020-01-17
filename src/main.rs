extern crate base64;
extern crate hex;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::error::Error;

fn find_most_used(v: &Vec<u8>) -> u8 {
    // count each character
    let mut counter = [0; 256];
    for c in v {
        counter[usize::from(*c)] += 1;
    }

    // find most used character
    let mut bigger = 0;
    let mut index: u8 = 0;
    for (i, c) in counter.iter().enumerate() {
        if bigger < *c {
            bigger = *c;
            index = i as u8;
        }
    }
    return index;
}

fn xor_string(s: &Vec<u8>, key: u8) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    for c in s {
        output.push(*c^key);
    }
    return output;
}

fn main () -> Result<(), Box<dyn Error>> {
    // fourth challenge:
    let filename = "4.txt";
    // Open the file in read-only mode (ignoring errors).
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);

    // Read the file line by line using the lines() iterator from std::io::BufRead.
    for line in reader.lines() {

        let line = line.unwrap(); // Ignore errors.
        let line = hex::decode(line).unwrap();

        if line.len() == 30 {
            // println!("{}", line);
            let key = find_most_used(&line);
            // println!("key: {}", key);
            let decoded = xor_string(&line, key ^ 0x65);

            let redecoded = match hex::decode(decoded) {
                Ok(s) => s,
                Err(_) => continue,
            };

            println!("redecoded {}", String::from_utf8(redecoded)?);
            // let hexstr = match hex::decode(&decoded) {
            //     Ok(s) => s,
            //     Err(_) => continue,
            // };

            // println!("ok!");
            // let hexstr = match String::from_utf8(hexstr) {
            //     Ok(s) => s,
            //     Err(_) => continue,
            // };

            // println!("WOHOOO");
            // println!("{}", hexstr);

            // let hexstr = match hex::decode(&hexstr) {
            //     Ok(s) => s,
            //     Err(_) => break,
            // };

            // println!("WOHOOO");
            // println!("{}", String::from_utf8(hexstr).unwrap());
        }
    }

    // let xored_str = hex::decode(&args[1])?;

    // // count each character
    // let mut counter = [0; 256];
    // for c in &xored_str {
    //     counter[usize::from(*c)] += 1;
    // }

    // // find most used character
    // let mut bigger = 0;
    // let mut index: u8 = 0;
    // for (i, c) in counter.iter().enumerate() {
    //     if bigger < *c {
    //         bigger = *c;
    //         index = i as u8;
    //     }
    // }

    // println!("e should be {}", index);
    // let mut output: Vec<u8> = Vec::new();
    // for c in xored_str {
    //     output.push(c^index);
    // }
    // println!("{}", String::from_utf8(output)?);

    Ok(())
}
   
